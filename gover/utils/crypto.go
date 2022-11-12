package utils

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path"
)

var keyMap = map[int]interface{}{}

const (
	DECRYPT_CHUNK_SIZE = 256
	ENCRYPT_CHUNK_SIZE = 256 - 11
)

const (
	CN_KEY       = 2
	OS_KEY       = 3
	SIGN_KEY     = 0
	CN1_KEY      = 4
	OS1_KEY      = 5
	CN_SIGN_KEY  = 1000 + 2
	OS_SIGN_KEY  = 1000 + 3
	CN1_SIGN_KEY = 1000 + 4
	OS1_SIGN_KEY = 1000 + 5
)

// toPrivateKey convert bytes to private key
func toPrivateKey(priv []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(priv)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// toPublicKey convert bytes to public key
func toPublicKey(pub []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pub)
	ifc, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := ifc.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("convert pubkey failed")
	}
	return key, nil
}

func loadKey(idx int, p string) error {
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	var key interface{}
	key, err = toPrivateKey(b)
	if err != nil {
		key, err = toPublicKey(b)
		if err != nil {
			return err
		}
	}
	keyMap[idx] = key
	return nil
}

func InitKey(p string) error {
	err := loadKey(CN_KEY, path.Join(p, "MHYPrivCN.pem"))
	if err != nil {
		return err
	}
	err = loadKey(OS_KEY, path.Join(p, "MHYPrivOS.pem"))
	if err != nil {
		return err
	}
	err = loadKey(SIGN_KEY, path.Join(p, "SigningKey.pem"))
	if err != nil {
		return err
	}
	err = loadKey(CN_SIGN_KEY, path.Join(p, "MHYSignCN.pem"))
	if err != nil {
		return err
	}
	err = loadKey(OS_SIGN_KEY, path.Join(p, "MHYSignOS.pem"))
	if err != nil {
		return err
	}
	err = loadKey(CN1_KEY, path.Join(p, "MHYPrivCN1.pem"))
	if err != nil {
		return err
	}
	err = loadKey(OS1_KEY, path.Join(p, "MHYPrivOS1.pem"))
	if err != nil {
		return err
	}
	err = loadKey(CN1_SIGN_KEY, path.Join(p, "MHYSignCN1.pem"))
	if err != nil {
		return err
	}
	err = loadKey(OS1_SIGN_KEY, path.Join(p, "MHYSignOS1.pem"))
	if err != nil {
		return err
	}
	return nil
}

func Decrypt(data []byte, idx int) ([]byte, error) {
	if i, ok := keyMap[idx]; ok {
		key := i.(*rsa.PrivateKey)
		out := make([]byte, 0, 1024)
		for len(data) > 0 {
			chunkSize := DECRYPT_CHUNK_SIZE
			if chunkSize > len(data) {
				chunkSize = len(data)
			}
			chunk := data[:chunkSize]
			data = data[chunkSize:]
			b, err := rsa.DecryptPKCS1v15(rand.Reader, key, chunk)
			if err != nil {
				return nil, err
			}
			out = append(out, b...)
		}
		return out, nil
	}
	return nil, errors.New("key not found")
}

func Sign(data []byte, idx int) ([]byte, error) {
	if key, ok := keyMap[idx]; ok {
		hashed := sha256.Sum256(data)
		return rsa.SignPKCS1v15(rand.Reader, key.(*rsa.PrivateKey), crypto.SHA256, hashed[:])
	}
	return nil, errors.New("key not found")
}

func Encrypt(data []byte, idx int) ([]byte, error) {
	if k, ok := keyMap[idx]; ok {
		var key *rsa.PublicKey
		if i, ok := k.(*rsa.PrivateKey); ok {
			key = &i.PublicKey
		} else if i, ok := k.(*rsa.PublicKey); ok {
			key = i
		}
		out := make([]byte, 0, 1024)
		for len(data) > 0 {
			chunkSize := ENCRYPT_CHUNK_SIZE
			if chunkSize > len(data) {
				chunkSize = len(data)
			}
			chunk := data[:chunkSize]
			data = data[chunkSize:]
			b, err := rsa.EncryptPKCS1v15(rand.Reader, key, chunk)
			if err != nil {
				return nil, err
			}
			out = append(out, b...)
		}
		return out, nil
	}
	return nil, errors.New("key not found")
}

func EncryptWithSign(data []byte, idx int) ([]byte, []byte, error) {
	encrypted, err := Encrypt(data, idx)
	if err != nil {
		return nil, nil, err
	}
	sign, err := Sign(data, SIGN_KEY)
	if err != nil {
		return nil, nil, err
	}
	return encrypted, sign, nil
}
