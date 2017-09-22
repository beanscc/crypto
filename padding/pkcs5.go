package padding

import (
	"bytes"
	"errors"
)

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	paddingText := bytes.Repeat([]byte{byte(padding)}, padding)

	return append(ciphertext, paddingText...)
}

func PKCS5Unpadding(origData []byte) ([]byte, error) {
	length := len(origData)
	unPadding := int(origData[length-1])
	if length < unPadding {
		// slice bounds out of range
		return nil, errors.New("PKCS5Unpadding err: slice bounds out of range")
	}

	return origData[:(length - unPadding)], nil
}
