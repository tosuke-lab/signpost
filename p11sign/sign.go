package p11sign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/miekg/pkcs11"
	"github.com/miekg/pkcs11/p11"
)

// from crypto/rsa/pkcs1v15.go
var hashPrefixes = map[crypto.Hash][]byte{
	crypto.MD5:       {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10},
	crypto.SHA1:      {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224:    {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256:    {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384:    {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512:    {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
	crypto.MD5SHA1:   {}, // A special TLS case which doesn't use an ASN1 prefix.
	crypto.RIPEMD160: {0x30, 0x20, 0x30, 0x08, 0x06, 0x06, 0x28, 0xcf, 0x06, 0x03, 0x00, 0x31, 0x04, 0x14},
}

type p11Key struct {
	sess       p11.Session
	privKey    p11.PrivateKey
	pubKey     PublicKey
	alwaysAuth bool
}

func NewKey(sess p11.Session, id []byte) (*p11Key, error) {
	pubKeyObj, err := sess.FindObject([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to find public key object: %w", err)
	}

	privKeyObj, err := sess.FindObject([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to find private key object: %w", err)
	}

	pubKey, err := GetP11PublicKey(p11.PublicKey(pubKeyObj))
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	alwaysAuthAttr, err := privKeyObj.Attribute(pkcs11.CKA_ALWAYS_AUTHENTICATE)
	if err != nil {
		if errors.Is(err, pkcs11.Error(pkcs11.CKR_ATTRIBUTE_TYPE_INVALID)) {
			alwaysAuthAttr = []byte{0}
		} else {
			return nil, fmt.Errorf("failed to get CKA_ALWAYS_AUTHENTICATE attribute: %w", err)
		}
	}
	alwaysAuth := len(alwaysAuthAttr) > 0 && alwaysAuthAttr[0] != 0

	return &p11Key{
		sess:       sess,
		privKey:    p11.PrivateKey(privKeyObj),
		pubKey:     pubKey,
		alwaysAuth: alwaysAuth,
	}, nil
}

func (k *p11Key) Public() crypto.PublicKey {
	return k.pubKey
}

func (k *p11Key) Label() (string, error) {
	return p11.Object(k.privKey).Label()
}

func (k *p11Key) AlwaysAuth() bool {
	return k.alwaysAuth
}

func (k *p11Key) Login(pin string) error {
	return k.sess.LoginAs(pkcs11.CKU_CONTEXT_SPECIFIC, pin)
}

func (k *p11Key) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	switch k.pubKey.(type) {
	case *rsa.PublicKey:
		switch opts.(type) {
		case *rsa.PSSOptions:
			return nil, errors.New("PSS signatures not supported")
		default: // PKCS1 v1.5
			return k.signRSAPKCSv15(digest, opts.HashFunc())
		}
	case *ecdsa.PublicKey:
		return k.signECDSA(digest)
	default:
		return nil, fmt.Errorf("unsupported key type: %T", k.pubKey)
	}
}

func (k *p11Key) signRSAPKCSv15(digest []byte, hashFunc crypto.Hash) ([]byte, error) {
	hashPrefix := hashPrefixes[hashFunc]
	if len(hashPrefix) == 0 {
		return nil, fmt.Errorf("unsupported hash function: %v", hashFunc)
	}

	hashed := append(hashPrefix, digest...)

	return k.privKey.Sign(*pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil), hashed)
}

type dsaSig struct {
	R, S *big.Int
}

func (k *p11Key) signECDSA(digest []byte) ([]byte, error) {
	sigBytes, err := k.privKey.Sign(*pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil), digest)
	if err != nil {
		if errors.Is(err, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)) {
			return nil, errors.New("ECDSA signing not supported")
		}
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	// 2.3.1. ECDSA Signature Format
	var sig dsaSig
	if len(sigBytes) == 0 || len(sigBytes)%2 != 0 {
		return nil, errors.New("invalid signature length")
	}
	n := len(sigBytes) / 2
	sig.R = new(big.Int).SetBytes(sigBytes[:n])
	sig.S = new(big.Int).SetBytes(sigBytes[n:])

	der, err := asn1.Marshal(sig)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signature: %w", err)
	}

	return der, nil
}
