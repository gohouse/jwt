package jwt

import (
	"github.com/dgrijalva/jwt-go"
	"testing"
)

func TestNewJWT(t *testing.T) {
	j := NewJWT(&Options{
		// 私钥：随机字符串
		Secret: "xxx",
		// 有效期：1小时
		Expire: 3600,
	})
	t.Log(j)
}

func TestJWT_CreateToken(t *testing.T) {
	j := NewJWT(&Options{
		// 私钥：随机字符串
		Secret: "xxx",
		// 有效期：1小时
		Expire: 3600,
	})
	token,err := j.CreateToken(CustomClaims{
		StandardClaims: jwt.StandardClaims{Issuer:"fizzday"},
		UserData: MapData{"mobile":13212341234,"role":"admin"},
	})
	if err!=nil {
		t.Error(err.Error())
	}
	t.Log(token)
}

func TestJWT_RefreshToken(t *testing.T) {
	j := NewJWT(&Options{
		// 私钥：随机字符串
		Secret: "xxx",
		// 有效期：1小时
		Expire: 3600,
	})
	token,err := j.CreateToken(CustomClaims{
		StandardClaims: jwt.StandardClaims{Issuer:"fizzday"},
		UserData:   MapData{"mobile":13212341234,"role":"admin"},
	})
	if err!=nil {
		t.Error(err.Error())
	}
	t.Log(token)

	token,err = j.RefreshToken(token)
	if err!=nil {
		t.Error(err.Error())
	}
	t.Log(token)
}

func TestJWT_ParseToken(t *testing.T) {
	j := NewJWT(&Options{
		// 私钥：随机字符串
		Secret: "xxx",
		// 有效期：1小时
		Expire: 3600,
	})
	token,err := j.CreateToken(CustomClaims{
		StandardClaims: jwt.StandardClaims{Issuer:"fizzday"},
		UserData:   MapData{"mobile":13212341234,"role":"admin"},
	})
	if err!=nil {
		t.Error(err.Error())
	}
	t.Log(token)

	claims,err := j.ParseToken(token)
	if err!=nil {
		t.Error(err.Error())
	}
	t.Log(claims)
}