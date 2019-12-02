# jwt
a simple jwt lib

## install 
```shell script
go get github.com/gohouse/jwt
```

## example
```go
package main

import (
	"fmt"
	"github.com/gohouse/jwt"
)

func main()  {
	j := jwt.NewJWT(&jwt.Options{
		// 私钥：随机字符串
		Secret: "xxx",
		// 有效期：1小时
		Expire: 3600,
	})
	token,err := j.CreateToken(CustomClaims{
		Data: jwt.MapData{"mobile":13212341234,"role":"admin"},
	})
	if err!=nil {
		fmt.Println(err.Error())
	}
	fmt.Println(token)
}
```