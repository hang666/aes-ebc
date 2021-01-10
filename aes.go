package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"os"
)

func main() {
	var origData, key string
	fmt.Println("Please enter your data:")
	Scanf(&origData)
	fmt.Println("Please enter your key:")
	Scanf(&key)


	// keyByte := []byte(key)

	//returnData := en(origData, key)
	returnData := de(origData, key)
	fmt.Println(returnData)

	fmt.Scan()
}

func en(origDataL string, key string) string{
	origDataByte := []byte(origDataL)
	encrypted := AesEncryptECB(origDataByte, key)
	base64Data := base64.StdEncoding.EncodeToString(encrypted)
	return base64Data
}

func de(origDataL string, key string) string{
	text, _ := base64.StdEncoding.DecodeString(origDataL)
	origDataByte := []byte(text)
	data := AesDecryptECB(origDataByte, key)
	return data
}

func AesEncryptECB(plaintext []byte, key string) []byte {
	plaintext = PKCS7Pad(plaintext)
	cipher, err := aes.NewCipher([]byte(key[:aes.BlockSize]))
	if err != nil {
		panic(err.Error())
	}

	if len(plaintext)%aes.BlockSize != 0 {
		panic("Need a multiple of the blocksize 16")
	}

	ciphertext := make([]byte, 0)
	text := make([]byte, 16)
	for len(plaintext) > 0 {
		// 每次运算一个block
		cipher.Encrypt(text, plaintext)
		plaintext = plaintext[aes.BlockSize:]
		ciphertext = append(ciphertext, text...)
	}
	return ciphertext
}

// 解密
func AesDecryptECB(ciphertext []byte, key string) string {
	cipher, err := aes.NewCipher([]byte(key[:aes.BlockSize]))
	if err != nil {
		panic(err.Error())
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		panic("Need a multiple of the blocksize 16")
	}

	plaintext := make([]byte, 0)
	text := make([]byte, 16)
	for len(ciphertext) > 0 {
		cipher.Decrypt(text, ciphertext)
		ciphertext = ciphertext[aes.BlockSize:]
		plaintext = append(plaintext, text...)
	}
	plaintext = PKCS7UPad(plaintext)
	return string(plaintext)
}

// Padding补全
func PKCS7Pad(data []byte) []byte {
	padding := aes.BlockSize - len(data)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(0)}, padding)
	return append(data, padtext...)
}

func PKCS7UPad(data []byte) []byte {
	padLength := int(data[len(data)-1])
	return data[:len(data)-padLength]
}

func Scanf(a *string) {
	reader := bufio.NewReader(os.Stdin)
	data, _, _ := reader.ReadLine()
	*a = string(data)
}

func inputData() string {
	var inputReader *bufio.Reader
	inputReader = bufio.NewReader(os.Stdin)
	str, _ := inputReader.ReadString('\n')
	return str
}
