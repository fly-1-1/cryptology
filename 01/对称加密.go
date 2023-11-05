package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
)

// DES的CBC加密
// 填充函数 如果最后一个分组字节数不够-填充 字节数刚好-添加新的分组
// 填充的字节的值--缺少的字节的数
func paddingLastGroup(plainText []byte, blockSize int) []byte {

	//求出最后一个组中剩下的字节数
	padNum := blockSize - len(plainText)%blockSize
	//创建新的切片 长度 == padNum ,每个字节的值 byte(padNum)
	char := []byte{byte(padNum)}
	newPlain := bytes.Repeat(char, padNum)
	//newPlain追加到原始明文后
	newText := append(plainText, newPlain...)
	return newText
}

// 去掉填充数据
func unPaddingLastGroup(plainText []byte) []byte {
	//拿出最后一个字节
	length := len(plainText)
	lastChar := plainText[length-1]
	// 尾部填充的字节个数
	number := int(lastChar)
	return plainText[:length-number]
}

// des加密
func desEncrypt(plaintText, key []byte) []byte {
	block, err := des.NewCipher(key)
	if err != nil {
		panic(err)
	}
	//2 明文填充
	newText := paddingLastGroup(plaintText, block.BlockSize())
	//3 创建使用cbc分组的接口
	iv := []byte("12345678")
	blockMod := cipher.NewCBCEncrypter(block, iv)
	//4 加密 通过blockMod
	cipherText := make([]byte, len(newText))
	blockMod.CryptBlocks(cipherText, newText)
	return cipherText
}

// des 解密
func desDecrypt(cipherText, key []byte) []byte {
	block, err := des.NewCipher(key)
	if err != nil {
		panic(err)
	}
	//2 创建一个使用cbc分组解密借口
	iv := []byte("12345678")
	blockMod := cipher.NewCBCDecrypter(block, iv)
	//3 解密
	blockMod.CryptBlocks(cipherText, cipherText)
	//4 cipherText存储的是明文 删除尾部填充的明文
	plaintText := unPaddingLastGroup(cipherText)
	return plaintText
}

// aes加密 计数器分组
func aesEncrypt(plaintText, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	//3 创建使用ctr分组的接口
	iv := []byte("12345678abcdefgh")
	stream := cipher.NewCTR(block, iv)
	//4 加密 通过blockMod
	cipherText := make([]byte, len(plaintText))
	stream.XORKeyStream(cipherText, plaintText)
	return cipherText
}

// des 解密
func aesDecrypt(cipherText, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	//2 创建一个使用cbc分组解密借口
	iv := []byte("12345678abcdefgh")
	stream := cipher.NewCTR(block, iv)
	//3 解密
	stream.XORKeyStream(cipherText, cipherText)
	return cipherText
}
