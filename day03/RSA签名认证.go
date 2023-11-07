package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func main() {
	src := []byte("大家好我是张家辉123123wdqwdqea3")
	sigText := SignatureRSA(src, "private.pem")
	bl := VerifyRSA(src, sigText, "public.pem")
	fmt.Println(bl)
}

// SignatureRSA RSA签名 私钥签名
func SignatureRSA(plaintText []byte, PublicFileName string) []byte {
	//1. 打开磁盘的私钥文件
	fp, err := os.Open(PublicFileName)
	if err != nil {
		panic(err)
	}
	//2. 将私钥文件中的内容读出
	info, err := fp.Stat()
	if err != nil {
		panic(err)
	}
	buf := make([]byte, info.Size())
	fp.Read(buf)
	fp.Close()
	//3. 使用pem对数据解码, 得到了pem.Block结构体变量
	block, _ := pem.Decode(buf)
	//4. x509将数据解析成私钥结构体 -> 得到了私钥
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	//5. 创建一个哈希对象 -> md5/sha1
	myHash := sha512.New()
	//6. 给哈希对象添加数据
	myHash.Write(plaintText)
	//7. 计算哈希值
	hashText := myHash.Sum(nil)
	//8. 使用rsa中的函数对散列值签名
	sigText, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA512, hashText)
	if err != nil {
		panic(err)
	}
	return sigText
}

// VerifyRSA RSA 签名验证
func VerifyRSA(plaintText, sigText []byte, pubFileName string) bool {
	//1. 打开公钥文件, 将文件内容读出 - []byte
	fp, err := os.Open(pubFileName)
	if err != nil {
		panic(err)
	}
	info, err := fp.Stat()
	if err != nil {
		panic(err)
	}
	buf := make([]byte, info.Size())
	fp.Read(buf)
	fp.Close()
	//2. 使用pem解码 -> 得到pem.Block结构体变量
	block, _ := pem.Decode(buf)
	//3. 使用x509对pem.Block中的Bytes变量中的数据进行解析 ->  得到一接口
	publicInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	//4. 进行类型断言 -> 得到了公钥结构体
	publicKey := publicInterface.(*rsa.PublicKey)
	//5. 对原始消息进行哈希运算(和签名使用的哈希算法一致) -> 散列值
	hashText := sha512.Sum512(plaintText)
	//6. 签名认证 - rsa中的函数
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA512, hashText[:], sigText)
	if err == nil {
		return true
	}
	return false
}
