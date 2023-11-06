package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// GeneralRsaKey 生成rsa的密钥对,并且保存到磁盘中
func GeneralRsaKey(keySize int) {
	//1 使用rsa中的GenerateKey方法生成私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		panic(err)
	}
	//2 通过x509标准将得到的ras私钥序列化为ASN.1 的 DER编码字符串
	derText := x509.MarshalPKCS1PrivateKey(privateKey)
	//3 要组织一个pem.Block结构体
	block := pem.Block{
		Type:  "rsa private key", //任意字符串
		Bytes: derText,
	}
	//4 通过pem将设置好的数据进行编码, 并写入磁盘文件中
	fp, err := os.Create("private.pem")

	if err != nil {
		panic(err)
	}
	pem.Encode(fp, &block)
	fp.Close()
	// 公钥
	// 1 从私钥中取出公钥
	publicKey := privateKey.PublicKey
	//2 使用x509标准序列化
	derStream, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		panic(derStream)
	}
	// 3 将格式化的数据放入pem.Block中
	block = pem.Block{
		Type:  "rse public key",
		Bytes: derStream,
	}
	fp, err = os.Create("public.pem")
	if err != nil {
		panic(err)
	}
	pem.Encode(fp, &block)
	fp.Close()
}

// RSAEncrypt RSA 加密 公钥加密
func RSAEncrypt(plaintText []byte, fileName string) []byte {
	// 1.打开文件,并且读出文件内容
	fp, err := os.Open(fileName)
	if err != nil {
		panic(err)
	}
	fileInfo, err := fp.Stat()
	if err != nil {
		panic(err)
	}
	buf := make([]byte, fileInfo.Size())
	fp.Read(buf)
	fp.Close()
	block, _ := pem.Decode(buf)
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	pubKey := pubInterface.(*rsa.PublicKey)
	//使用公钥加密
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, plaintText)
	if err != nil {
		panic(err)
	}
	return cipherText
}

// RSADecrypt RSA 解密
func RSADecrypt(cipherText []byte, fileName string) []byte {
	// 1.打开文件,并且读出文件内容
	fp, err := os.Open(fileName)
	if err != nil {
		panic(err)
	}
	fileInfo, err := fp.Stat()
	if err != nil {
		panic(err)
	}
	buf := make([]byte, fileInfo.Size())
	fp.Read(buf)
	fp.Close()
	block, _ := pem.Decode(buf)
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	//使用私钥解密
	plaintText, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, cipherText)
	if err != nil {
		panic(err)
	}
	return plaintText
}

func main() {
	GeneralRsaKey(1024)
	src := []byte("这里是密码学加密测试文本")
	cipherText := RSAEncrypt(src, "public.pem")
	fmt.Println(string(cipherText))
	plaintText := RSADecrypt(cipherText, "private.pem")
	fmt.Println(string(plaintText))
}
