package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"github.com/elliotchance/phpserialize"
	"io"
	"bytes"
	"crypto/rand"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"os"
)

func main()  {

	//加密
	token, err := encode("jiangshengxin")
	if err != nil {

	}
	println(token)
	os.Exit(1)


	//解密
	str, err := decode("eyJpdiI6IkJLZmJoOTBGa1A0MGRiLy8zemg4c1E9PSIsIm1hYyI6IjAzZDZiZGQ5YWY4NGY2NGZkMTgwMmFjZTFkZWMwNDgzM2I4ZmUyZTUzOTI2OGY5ZjEzNDQ1OGMwMWE2YmYxYzYiLCJ2YWx1ZSI6IlBqQ1llMW81eFlIZUppaEgyQldrdWxpQzNRb3kyaHNCb0hlS1JTTDR0b2s9In0=")
	if err != nil {

	}
	println(str)
	os.Exit(2)

}


//加密
func encode(ciphertext string) (string,error) {

	//初始化密钥
	key:= []byte("1a04c2a6bl6341639118a9bdbbea545a")

	//序列化密文
	ciphertextNew,err := phpserialize.Marshal(ciphertext,nil)
	if err != nil {
		return "",err
	}
	plaintext := []byte(ciphertextNew)

	//填充明文至加密要求长度
	/*	paddingCount := aes.BlockSize - len(plaintext)%aes.BlockSize
		if paddingCount != 0 {
			plaintext = append(plaintext, bytes.Repeat([]byte{byte(0)}, paddingCount)...)
		}*/
	plaintext,err = Pad(plaintext,aes.BlockSize)
	if err != nil {
		return "",err
	}

	// CBC mode works on blocks so plaintexts may need to be padded to the
	// next whole block. For an example of such padding, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. Here we'll
	// assume that the plaintext is already of the correct length.
	//检查密文长度是否合法
	/*if len(plaintext)%aes.BlockSize != 0 {
		return "",err
	}*/

	block, err := aes.NewCipher(key)
	if err != nil {
		return "",err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "",err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(plaintext, plaintext)

	//原加密算法
	/*type payload struct {
		IV string
		Value string
		Mac string
	}
	p := payload{}
	p.IV = base64.StdEncoding.EncodeToString(iv)
	p.Value = base64.StdEncoding.EncodeToString(plaintext)
	data, err := json.Marshal(p)*/
	//现在加密算法
	payload := make(map[string]string)
	payload["iv"] = base64.StdEncoding.EncodeToString(iv)
	payload["value"] = base64.StdEncoding.EncodeToString(plaintext)
	//生成mac
	h := hmac.New(sha256.New,[]byte(key))
	io.WriteString(h,payload["iv"]+payload["value"])
	payload["mac"] = fmt.Sprintf("%x", h.Sum(nil))

	//转json
	data, err := json.Marshal(payload)

	if err != nil {
		return "",err
	}
	ciphertext = base64.StdEncoding.EncodeToString(data)
	return ciphertext,nil
}


//解密
func decode(ciphertext string) (string, error) {

	//初始化密钥
	key:= "1a04c2a6bl6341639118a9bdbbea545a"

	decodeBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", errors.New("ciphertext value must in base64 format")
	}
	var payload struct {
		IV    string
		Value string
		Mac   string
	}
	err = json.Unmarshal(decodeBytes, &payload)
	if err != nil {
		return "", errors.New("ciphertext value must be valid")
	}
	encryptedText, err := base64.StdEncoding.DecodeString(payload.Value)
	if err != nil {
		return "", errors.New("encrypted text must be valid base64 format")
	}
	iv, err := base64.StdEncoding.DecodeString(payload.IV)
	if err != nil {
		return "", errors.New("iv in payload must be valid base64 format")
	}
	var keyBytes []byte
	if strings.HasPrefix(key, "base64:") {
		keyBytes, err = base64.StdEncoding.DecodeString(string(key[7:]))
		if err != nil {
			return "", errors.New("seems like you provide a key in base64 format, but it's not valid")
		}
	} else {
		keyBytes = []byte(key)
	}
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(encryptedText, encryptedText)
	var cleartext string
	err = phpserialize.Unmarshal(encryptedText, &cleartext)
	return cleartext, nil
}

//ase-256-cbc长度填充
func Pad(src []byte, blockSize int) ([]byte, error) {
	// 按标准只允许1 - 255个大小的块.
	if blockSize < 1 || blockSize > 255 {
		return nil, errors.New("pkcs7: block size must be between 1 and 255 inclusive")
	}

	// 通过设定目标块大小来计算所需填充的长度
	// 减去源的溢出
	padLen := blockSize - len(src)%blockSize

	// 将包含要重复的字节的字节片.
	padding := []byte{byte(padLen)}

	// 重复那个字节padLen时间
	padding = bytes.Repeat(padding, padLen)

	// 向src追加填充.
	return append(src, padding...), nil
}