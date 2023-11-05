package main

import (
	"fmt"
)

func main() {
	key := []byte("1234abcd")
	src := []byte("大家好我是张家辉123123wdqwdqea3")
	cipher := desEncrypt(src, key)
	fmt.Println(string(cipher))
	plaintText := desDecrypt(cipher, key)
	fmt.Println(string(plaintText))

	key = []byte("1234abcd12345678")
	cipher = aesEncrypt(src, key)
	fmt.Println(string(cipher))
	plaintText = aesDecrypt(cipher, key)
	fmt.Println(string(plaintText))

}
