package jwt

import (
	"errors"
	jwtlib "github.com/dgrijalva/jwt-go"
	"time"
)

// 一些常量
var (
	// TokenExpired ...
	TokenExpired = errors.New("Token is expired")
	// TokenNotValidYet ...
	TokenNotValidYet = errors.New("Token not active yet")
	// TokenMalformed ...
	TokenMalformed = errors.New("That's not even a token")
	// TokenInvalid ...
	TokenInvalid = errors.New("Couldn't handle this token:")
)

// MapData ...
type MapData map[string]interface{}

// 载荷，可以加一些自己需要的信息
type CustomClaims struct {
	jwtlib.StandardClaims
	UserData MapData
}

// Options ...
type Options struct {
	Secret string `json:"secret"`
	Expire int64  `json:"expire"`
}

// JWT 签名结构
type JWT struct {
	*Options
	SigningKey []byte
}

// 新建一个jwt实例
func NewJWT(o *Options) *JWT {
	if o.Secret == "" {
		panic("secret can't be empty")
	}
	if o.Expire == 0 {
		o.Expire = 60 * 60 * 8
	}
	return &JWT{
		Options:    o,
		SigningKey: []byte(o.Secret),
	}
}

// CreateToken 生成一个token
func (j *JWT) CreateToken(claims CustomClaims) (string, error) {
	// 设置过期时间
	expireAt := time.Now().Add(time.Second * time.Duration(j.Options.Expire)).Unix()
	claims.ExpiresAt = expireAt

	token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims)
	return token.SignedString(j.SigningKey)
}

// 解析Token
func (j *JWT) ParseToken(tokenString string) (*CustomClaims, error) {
	token, err := jwtlib.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwtlib.Token) (interface{}, error) {
		return j.SigningKey, nil
	})
	if err != nil {
		if ve, ok := err.(*jwtlib.ValidationError); ok {
			if ve.Errors&jwtlib.ValidationErrorMalformed != 0 {
				return nil, TokenMalformed
			} else if ve.Errors&jwtlib.ValidationErrorExpired != 0 {
				// Token is expired
				return nil, TokenExpired
			} else if ve.Errors&jwtlib.ValidationErrorNotValidYet != 0 {
				return nil, TokenNotValidYet
			} else {
				return nil, TokenInvalid
			}
		}
	}
	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, TokenInvalid
}

// 更新token
func (j *JWT) RefreshToken(tokenString string) (string, error) {
	jwtlib.TimeFunc = func() time.Time {
		return time.Unix(0, 0)
	}
	token, err := jwtlib.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwtlib.Token) (interface{}, error) {
		return j.SigningKey, nil
	})
	if err != nil {
		return "", err
	}
	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		jwtlib.TimeFunc = time.Now
		claims.StandardClaims.ExpiresAt = time.Now().Add(time.Second * time.Duration(j.Options.Expire)).Unix()
		return j.CreateToken(*claims)
	}
	return "", TokenInvalid
}
