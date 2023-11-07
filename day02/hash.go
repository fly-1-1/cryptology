package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// 使用sha256
func myHash() {
	//sha256.Sum256([]byte("hello hash"))
	//1 创建哈希借口对象
	myHash := sha256.New()
	//2 添加数据
	src := []byte("hello hash")
	myHash.Write(src)
	myHash.Write(src)
	myHash.Write(src)
	//3 计算结果
	res := myHash.Sum(nil)
	//4 格式化
	myStr := hex.EncodeToString(res)
	fmt.Println(myStr)
}

func main() {
	myHash()
}
