package p11sign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/miekg/pkcs11"
	"github.com/miekg/pkcs11/p11"
)

func FindPublicKeyObject(sess p11.Session, pubKey crypto.PublicKey) (p11.Object, error) {
	switch pubKey := pubKey.(type) {
	case *rsa.PublicKey:
		return findRSAPublicKeyObject(sess, pubKey)
	case *ecdsa.PublicKey:
		return findECDSAPublicKeyObject(sess, pubKey)
	default:
		return p11.Object{}, fmt.Errorf("unsupported public key type: %T", pubKey)
	}
}

func findRSAPublicKeyObject(sess p11.Session, pubKey *rsa.PublicKey) (p11.Object, error) {
	return sess.FindObject([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, pubKey.N.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, big.NewInt(int64(pubKey.E)).Bytes()),
	})
}

var curveOIDs = map[string]asn1.ObjectIdentifier{
	"P-224": {1, 3, 132, 0, 33},
	"P-256": {1, 2, 840, 10045, 3, 1, 7},
	"P-384": {1, 3, 132, 0, 34},
	"P-521": {1, 3, 132, 0, 35},
}

func findECDSAPublicKeyObject(sess p11.Session, pubKey *ecdsa.PublicKey) (p11.Object, error) {
	pointASN1 := elliptic.Marshal(pubKey.Curve, pubKey.X, pubKey.Y)
	pointDER, err := asn1.Marshal(pointASN1)
	if err != nil {
		return p11.Object{}, fmt.Errorf("failed to marshal EC point: %w", err)
	}

	curveName := pubKey.Curve.Params().Name
	ecParamsOID, ok := curveOIDs[curveName]
	if !ok {
		return p11.Object{}, fmt.Errorf("unsupported curve: %s", curveName)
	}
	ecParamsDER, err := asn1.Marshal(ecParamsOID)
	if err != nil {
		return p11.Object{}, fmt.Errorf("failed to marshal EC params: %w", err)
	}

	return sess.FindObject([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParamsDER),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, pointDER),
	})
}

type PublicKey interface {
	crypto.PublicKey

	Equal(pk crypto.PublicKey) bool
}

func GetP11PublicKey(pk p11.PublicKey) (PublicKey, error) {
	pko := p11.Object(pk)
	keyTypeAttr, err := pko.Attribute(pkcs11.CKA_KEY_TYPE)
	if err != nil {
		return nil, fmt.Errorf("failed to get key type attribute: %w", err)
	}
	keyType := new(big.Int).SetBytes(keyTypeAttr).Uint64()

	switch keyType {
	case pkcs11.CKK_RSA:
		return getP11RSAPublicKey(pko)
	case pkcs11.CKK_EC:
		return getP11ECDSAPublicKey(pko)
	default:
		return nil, fmt.Errorf("unsupported key type: %d", keyType)
	}
}

func getP11RSAPublicKey(pko p11.Object) (PublicKey, error) {
	modulusAttr, err := pko.Attribute(pkcs11.CKA_MODULUS)
	if err != nil {
		return nil, fmt.Errorf("failed to get modulus attribute: %w", err)
	}
	modulus := new(big.Int).SetBytes(modulusAttr)

	exponentAttr, err := pko.Attribute(pkcs11.CKA_PUBLIC_EXPONENT)
	if err != nil {
		return nil, fmt.Errorf("failed to get public exponent attribute: %w", err)
	}
	exponent := int(new(big.Int).SetBytes(exponentAttr).Uint64())

	return &rsa.PublicKey{
		N: modulus,
		E: exponent,
	}, nil
}

func getP11ECDSAPublicKey(pko p11.Object) (PublicKey, error) {
	ecParamsDER, err := pko.Attribute(pkcs11.CKA_EC_PARAMS)
	if err != nil {
		return nil, fmt.Errorf("failed to get EC params attribute: %w", err)
	}
	ecPointDER, err := pko.Attribute(pkcs11.CKA_EC_POINT)
	if err != nil {
		return nil, fmt.Errorf("failed to get EC point attribute: %w", err)
	}

	curve, err := parseECParamsDER(ecParamsDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EC params: %w", err)
	}

	var pointBuf []byte
	extra, err := asn1.Unmarshal(ecPointDER, &pointBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal EC point: %w", err)
	} else if len(extra) > 0 {
		return nil, fmt.Errorf("extra data in EC point")
	}

	x, y := elliptic.Unmarshal(curve, pointBuf)
	if x == nil || y == nil {
		return nil, fmt.Errorf("failed to unmarshal EC point")
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

func parseECParamsDER(der []byte) (curve elliptic.Curve, err error) {
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(der, &oid); err != nil {
		return nil, fmt.Errorf("failed to unmarshal EC params: %w", err)
	}

	// RFC 5480, 2.1.1.1. Named Curve
	switch oid.String() {
	case "1.2.840.10045.3.1.1": // secp192r1
		return nil, fmt.Errorf("unsupported curve: secp192r1")
	case "1.3.132.0.1": // sect163k1
		return nil, fmt.Errorf("unsupported curve: sect163k1")
	case "1.3.132.0.15": // sect163r2
		return nil, fmt.Errorf("unsupported curve: sect163r2")
	case "1.3.132.0.33": // secp224r1
		return elliptic.P224(), nil
	case "1.3.132.0.26": // sect233k1
		return nil, fmt.Errorf("unsupported curve: sect233k1")
	case "1.3.132.0.27": // sect233r1
		return nil, fmt.Errorf("unsupported curve: sect233r1")
	case "1.2.840.10045.3.1.7": // secp256r1
		return elliptic.P256(), nil
	case "1.3.132.0.16": // sect283k1
		return nil, fmt.Errorf("unsupported curve: sect283k1")
	case "1.3.132.0.17": // sect283r1
		return nil, fmt.Errorf("unsupported curve: sect283r1")
	case "1.3.132.0.34": // secp384r1
		return elliptic.P384(), nil
	case "1.3.132.0.36": // sect409k1
		return nil, fmt.Errorf("unsupported curve: sect409k1")
	case "1.3.132.0.37": // sect409r1
		return nil, fmt.Errorf("unsupported curve: sect409r1")
	case "1.3.132.0.35": // secp521r1
		return elliptic.P521(), nil
	case "1.3.132.0.38": // sect571k1
		return nil, fmt.Errorf("unsupported curve: sect571k1")
	case "1.3.132.0.39": // sect571r1
		return nil, fmt.Errorf("unsupported curve: sect571r1")
	}

	return nil, fmt.Errorf("unknown curve: %v", oid.String())
}
