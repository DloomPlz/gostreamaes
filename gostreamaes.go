package gostreamaes

import (
	"crypto/aes"
	"crypto/cipher"
	"io"
)

type Aes struct {
	enc, dec cipher.BlockMode
}

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
