# golang写的与php框架laravel内置安全---加密算法对接
> 附上: laravel内部安全加密算法/golang安全加密算法<br>
> 内有demo示例

## PHP
```php
$aes = new Encrypter();
echo $aes->encrypt('exampleplaintext')."\n";
echo $aes->decrypt("eyJpdiI6IkJLZmJoOTBGa1A0MGRiLy8zemg4...");
```

## GO
```go
// crypto/aes、crypto/hmac、crypto/sha256、encoding/base64
// encrypt.go
```

