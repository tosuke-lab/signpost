package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"

	"github.com/miekg/pkcs11"
	"github.com/miekg/pkcs11/p11"
	"github.com/tosuke-lab/signpost/p11sign"
	"golang.org/x/term"
)

func main() {
	pkcs11Provider := "/usr/lib/opensc-pkcs11.so"
	caCertPath := "9d.crt"

	module, err := p11.OpenModule(pkcs11Provider)
	if err != nil {
		panic(fmt.Errorf("failed to open module: %w", err))
	}
	defer module.Destroy()

	slots, err := module.Slots()
	if err != nil {
		panic(fmt.Errorf("failed to get slots: %w", err))
	}

	var slot p11.Slot
	for _, slot = range slots {
		if slot.ID() == 0 {
			break
		}
	}
	sess, err := slot.OpenSession()
	if err != nil {
		panic(fmt.Errorf("failed to open session: %w", err))
	}

	caCertFile, err := os.Open(caCertPath)
	if err != nil {
		panic(err)
	}

	defer caCertFile.Close()

	caCertPEM, err := io.ReadAll(caCertFile)
	if err != nil {
		panic(err)
	}

	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		panic("failed to decode PEM block")
	} else if caCertBlock.Type != "CERTIFICATE" {
		panic(fmt.Errorf("ca cert has invalid type: %s", caCertBlock.Type))
	}

	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		panic(fmt.Errorf("failed to parse ca certificate: %w", err))
	}

	if !caCert.IsCA {
		panic("ca cert is not a CA")
	}

	pubKeyObj, err := p11sign.FindPublicKeyObject(sess, caCert.PublicKey)
	if err != nil {
		panic(fmt.Errorf("failed to find public key object: %w", err))
	}

	id, err := pubKeyObj.Attribute(pkcs11.CKA_ID)
	if err != nil {
		panic(fmt.Errorf("failed to get id: %w", err))
	}

	tokenInfo, err := slot.TokenInfo()
	if err != nil {
		panic(fmt.Errorf("failed to get token info: %w", err))
	}
	fmt.Printf("PIN for %s: ", tokenInfo.Label)
	pinBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		panic(fmt.Errorf("failed to read password: %w", err))
	}
	fmt.Println()
	if err := sess.Login(string(pinBytes)); err != nil {
		if errors.Is(err, pkcs11.Error(pkcs11.CKR_PIN_INCORRECT)) || errors.Is(err, pkcs11.Error(pkcs11.CKR_PIN_LEN_RANGE)) {
			fmt.Println("incorrect PIN")
			return
		} else {
			panic(fmt.Errorf("failed to login: %w", err))
		}
	}

	caKey, err := p11sign.NewKey(sess, id)
	if err != nil {
		panic(fmt.Errorf("failed to create key: %w", err))
	}

	random := rand.Reader

	key, err := rsa.GenerateKey(random, 2048)
	if err != nil {
		panic(err)
	}

	randomBytes := make([]byte, 20)
	io.ReadFull(random, randomBytes)
	serialNumber := new(big.Int).SetBytes(randomBytes)

	subject := pkix.Name{
		CommonName:   "tosuke",
		Organization: []string{"system:masters"},
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(6 * time.Hour)

	certTemplate := x509.Certificate{
		SerialNumber: serialNumber,

		Subject: subject,

		NotBefore: notBefore,
		NotAfter:  notAfter,

		BasicConstraintsValid: true,
		IsCA:                  false,

		KeyUsage: x509.KeyUsageEncipherOnly | x509.KeyUsageDataEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
	}

	if caKey.AlwaysAuth() {
		label, err := caKey.Label()
		if err != nil {
			panic(fmt.Errorf("failed to get label: %w", err))
		}
		fmt.Printf("PIN for %s: ", label)

		pinBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			panic(fmt.Errorf("failed to read password: %w", err))
		}
		fmt.Println()

		if err := caKey.Login(string(pinBytes)); err != nil {
			if errors.Is(err, pkcs11.Error(pkcs11.CKR_PIN_INCORRECT)) || errors.Is(err, pkcs11.Error(pkcs11.CKR_PIN_LEN_RANGE)) {
				fmt.Println("incorrect PIN")
				return
			} else {
				panic(fmt.Errorf("failed to login: %w", err))
			}
		}
	}

	certDER, err := x509.CreateCertificate(random, &certTemplate, caCert, key.Public(), caKey)
	if err != nil {
		panic(fmt.Errorf("failed to create certificate: %w", err))
	}

	clientCrtFile, err := os.OpenFile("client.crt", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(fmt.Errorf("failed to open client.crt: %w", err))
	}
	defer clientCrtFile.Close()

	if err := pem.Encode(clientCrtFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}); err != nil {
		panic(fmt.Errorf("failed to encode client.crt: %w", err))
	}

	if _, err := io.Copy(clientCrtFile, bytes.NewBuffer(caCertPEM)); err != nil {
		panic(fmt.Errorf("failed to write client certificate: %w", err))
	}

	keyPEM, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(fmt.Errorf("failed to marshal private key: %w", err))
	}

	clientKeyFile, err := os.OpenFile("client.key", os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		panic(fmt.Errorf("failed to open client.key: %w", err))
	}
	defer clientKeyFile.Close()

	if err := pem.Encode(clientKeyFile, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyPEM,
	}); err != nil {
		panic(fmt.Errorf("failed to encode client.key: %w", err))
	}
}
