package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"

	"github.com/beanscc/crypto/padding"
)

// CBCEncrypt aes cbc模式加密
// plaintext 需加密的明文
// key	     加密key， 长度说明：16(aes-128), 24(aes-192), 32(aes-256)
// iv        密钥偏移量16字节长度
func CBCEncrypt(plaintext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// iv 密钥偏移量长度不足16
	if iv == nil || len(iv) < 16 {
		return nil, errors.New("IV length must equal block size")
	}

	// 若加密明文的字节长度不是16的整数倍, 需将明文字符串填充补齐至16的整数倍字节长度
	plaintext = padding.PKCS5Padding(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.

	return ciphertext, nil
}

// CBCDecrypt aes cbc 解密
func CBCDecrypt(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		// 加密字符串数据区块长度不够，即加密字符串不完整
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(plaintext, ciphertext)

	// 需去除填充
	plaintext, err = padding.PKCS5Unpadding(plaintext)
	if err != nil {
		// unpadding err (可能是解密的字符串和key长度不匹配(或解密key值不对)导致无法正常unpadding)
		return nil, err
	}

	return plaintext, nil
}
