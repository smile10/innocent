package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

const RSA_KEY_SIZE = 4096

type RSAKeyPair struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

func NewRandomRSAKeyPair(keysize int) (*RSAKeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, keysize)
	if err != nil {
		return nil, err
	}

	return &RSAKeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}, nil
}

func ExportRSAPrivateKeyToPem(privateKey *rsa.PrivateKey) string {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyBytes,
		},
	)

	return string(privateKeyPem)
}

func ImportRSAPrivateKeyFromPem(privteKeyPem string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privteKeyPem))
	if block == nil {
		return nil, errors.New("failed to read PEM block containing the key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func ExportRSAPublicKeyToPem(publicKey *rsa.PublicKey) (string, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}

	publicKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: publicKeyBytes,
		},
	)

	return string(publicKeyPem), nil
}

func ImportRSAPublicKeyFromPem(publicKeyPem string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPem))
	if block == nil {
		return nil, errors.New("failed to read PEM block containing the key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch p := publicKey.(type) {
	case *rsa.PublicKey:
		return p, nil
	default:
		break // fall through
	}
	return nil, errors.New("key type is not RSA")
}

func RSAEncrypt(plaintext []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	var err error
	var ciphertext []byte
	chunkSize := publicKey.Size() - 2*sha256.New().Size() - 2

	if len(plaintext) > chunkSize {
		for i := 0; i < len(plaintext); i += chunkSize {
			end := i + chunkSize
			if end > len(plaintext) {
				end = len(plaintext)
			}
			chunk := plaintext[i:end]

			cipherChunk, err := rsa.EncryptOAEP(
				sha256.New(),
				rand.Reader,
				publicKey,
				chunk,
				nil,
			)
			if err != nil {
				return nil, err
			}
			ciphertext = append(ciphertext, cipherChunk...)
		}
	} else {
		ciphertext, err = rsa.EncryptOAEP(
			sha256.New(),
			rand.Reader,
			publicKey,
			plaintext,
			nil,
		)
		if err != nil {
			return nil, err
		}
	}

	return ciphertext, nil
}

func RSADecrypt(ciphertext []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	chunkSize := privateKey.Size()
	var plaintext []byte
	var err error

	if len(ciphertext) > chunkSize {
		for i := 0; i < len(ciphertext); i += chunkSize {
			chunk := ciphertext[i : i+chunkSize]
			plainChunk, err := rsa.DecryptOAEP(
				sha256.New(),
				rand.Reader,
				privateKey,
				chunk,
				nil,
			)
			if err != nil {
				return nil, fmt.Errorf("decryption failed at chunk %d: %v", i/chunkSize, err)
			}

			plaintext = append(plaintext, plainChunk...)
		}
	} else {
		plaintext, err = rsa.DecryptOAEP(
			sha256.New(),
			rand.Reader,
			privateKey,
			ciphertext,
			nil,
		)
		if err != nil {
			return nil, err
		}
	}

	return plaintext, nil
}
