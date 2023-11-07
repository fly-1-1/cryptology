package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"fmt"
)

func main03() {

	src := []byte("张家辉一刀九九九")
	key := []byte("hello")
	hmac1 := GeneralHmac(src, key)
	bl := VerifyHmac(src, key, hmac1)
	fmt.Println("校验结果:", bl)
}

// GeneralHmac 生成消息验证码的函数
func GeneralHmac(plaintText, key []byte) []byte {
	//1.创建哈希接口 需要指定哈希算法与秘钥
	myhash := hmac.New(sha1.New, key)
	//2. 添加数据
	myhash.Write(plaintText)
	//3. 计算散列值
	hashText := myhash.Sum(nil)
	//hex.EncodeToString(hashText)
	return hashText
}

// VerifyHmac 校验消息验证码
func VerifyHmac(plaintText, key, hashText []byte) bool {
	//1.创建哈希接口 需要指定哈希算法与秘钥
	myhash := hmac.New(sha1.New, key)
	//2. 添加数据
	myhash.Write(plaintText)
	//3. 计算散列值
	hmac1 := myhash.Sum(nil)
	//4. 对比两个散列值
	return hmac.Equal(hmac1, hashText)
}
