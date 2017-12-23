package gostreamaes

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
)

type Aes struct {
	enc, dec cipher.BlockMode
}

// Creates a new encryption/decryption object
// with a given key of a given size
// (16, 24 or 32 for AES-128, AES-192 and AES-256 respectively,
// as per http://golang.org/pkg/crypto/aes/#NewCipher)
//
// The key will be padded to the given size if needed.
// An IV is created as a series of NULL bytes of necessary length
// when there is no iv string passed as 3rd value to function.
func NewAESObject(size int, key string, more ...string) (*Aes, error) {

	padded := make([]byte, size)

	copy(padded, []byte(key))

	var iv []byte
	if len(more) > 0 {
		iv = []byte(more[0])

	} else {
		iv = make([]byte, size)

	}

	aes, err := aes.NewCipher(padded)

	if err != nil {
		return nil, err
	}

	enc := cipher.NewCBCEncrypter(aes, iv)

	dec := cipher.NewCBCDecrypter(aes, iv)

	return &Aes{enc, dec}, nil
}

// Encrypt blocks from reader, write results into writer
func (me *Aes) EncryptStream(reader io.Reader, writer io.Writer) error {
	buf := make([]byte, me.enc.BlockSize())
	for {
		_, err := io.ReadFull(reader, buf)
		if err != nil {
			if err == io.EOF {
				break
			} else if err == io.ErrUnexpectedEOF {
				// nothing
			} else {
				return err
			}
		}
		me.enc.CryptBlocks(buf, buf)
		if _, err = writer.Write(buf); err != nil {
			return err
		}
	}
	return nil
}

// Decrypt blocks from reader, write results into writer
func (me *Aes) DecryptStream(reader io.Reader, writer io.Writer) error {
	buf := make([]byte, me.dec.BlockSize())
	for {
		_, err := io.ReadFull(reader, buf)
		if err != nil {
			if err == io.EOF {
				break
			} else {
				return err
			}
		}
		me.dec.CryptBlocks(buf, buf)
		if _, err = writer.Write(buf); err != nil {
			return err
		}
	}
	return nil
}
