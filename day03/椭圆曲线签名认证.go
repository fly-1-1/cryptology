package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
)

func main() {
	GeneralEccKey()
	src := []byte("张家辉一刀九九九")
	r, s := EccSignature(src, "eccPrivate.pem")
	bl := EccVerify(src, r, s, "eccPublic.pem")
	fmt.Println(bl)
}

// GeneralEccKey  生成秘钥
func GeneralEccKey() {
	//1. 使用ecdsa生成密钥对
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		panic(err)
	}
	//2. 将私钥写入磁盘
	//使用x509进行序列化
	derText, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		panic(err)
	}
	//- 将得到的切片字符串放入pem.Block结构体中
	block := pem.Block{
		Type:  "ecdsa private key",
		Bytes: derText,
	}
	//- 使用pem编码
	fp, err := os.Create("eccPrivate.pem")
	if err != nil {
		panic(err)
	}
	//pem.Encode();
	pem.Encode(fp, &block)
	fp.Close()
	//3. 将公钥写入磁盘
	//- 从私钥中得到公钥
	publicKey := privateKey.PublicKey
	//- 使用x509进行序列化
	derText, err = x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		panic(err)
	}
	//- 将得到的切片字符串放入pem.Block结构体中
	block = pem.Block{
		Type:  "ecdsa public key",
		Bytes: derText,
	}
	//- 使用pem编码
	fp, err = os.Create("eccPublic.pem")
	if err != nil {
		panic(err)
	}
	pem.Encode(fp, &block)
	fp.Close()
}

// EccSignature ecc签名
func EccSignature(plaintText []byte, privName string) (rText, sText []byte) {
	//1. 打开私钥文件, 将内容读出来 ->[]byte
	fp, err := os.Open(privName)
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
	//2. 使用pem进行数据解码 -> pem.Decode()
	block, _ := pem.Decode(buf)
	//3. 使用x509, 对私钥进行还原
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	//4. 对原始数据进行哈希运算 -> 散列值
	hashText := sha1.Sum(plaintText)
	//5. 进行数字签名
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashText[:])
	if err != nil {
		panic(err)
	}
	// r,s 格式化 --> []byte
	rText, err = r.MarshalText()
	if err != nil {
		panic(err)
	}
	sText, err = s.MarshalText()
	if err != nil {
		panic(err)
	}
	return rText, sText
}

// EccVerify ECC 签名认证
func EccVerify(plaintText, rText, sText []byte, pubFile string) bool {
	//1. 打开公钥文件, 将里边的内容读出 -> []byte
	fp, err := os.Open(pubFile)
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
	//2. pem解码 -> pem.Decode()
	block, _ := pem.Decode(buf)
	//3. 使用x509对公钥还原
	publicInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	//4. 将接口 -> 公钥
	publicKey := publicInterface.(*ecdsa.PublicKey)
	//5. 对原始数据进行哈希运算 -> 得到散列值
	hashText := sha1.Sum(plaintText)
	//6. 签名的认证 - > ecdsa
	var r, s big.Int
	r.UnmarshalText(rText)
	s.UnmarshalText(sText)
	return ecdsa.Verify(publicKey, hashText[:], &r, &s)
}
