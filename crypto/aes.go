package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

type AESKey []byte

func AESEncrypt(plain []byte, key AESKey) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	cypher := gcm.Seal(nonce, nonce, plain, nil)

	return cypher, nil
}

func AESDecyrpt(cypher []byte, key AESKey) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plain, err := gcm.Open(nil, cypher[:gcm.NonceSize()], cypher[gcm.NonceSize():], nil)
	if err != nil {
		return nil, err
	}

	return plain, nil
}

func NewRandomAESKey(keysize int) (AESKey, error) {
	key := make([]byte, keysize)

	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		return nil, err
	}

	return key, nil
}
