package utils

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/uyabpras/go-grpc-auth-svc/pkg/models"
)

type JwtWrapper struct {
	SecretKey       string
	Issuer          string
	ExpirationHours int64
}

type jwtClaims struct {
	jwt.StandardClaims
	ID    int64
	Email string
}

func (w *JwtWrapper) GenerateToken(user models.User) (signedToken string, err error) {
	claims := &jwtClaims{
		ID:    user.ID,
		Email: user.Email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * time.Duration(w.ExpirationHours)).Unix(),
			Issuer:    w.Issuer,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err = token.SignedString([]byte(w.SecretKey))

	if err != nil {
		return "", err
	}
	return signedToken, nil
}

func (w *JwtWrapper) ValidateToken(signedtoken string) (claims *jwtClaims, err error) {
	token, err := jwt.ParseWithClaims(
		signedtoken,
		&jwtClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(w.SecretKey), nil
		},
	)

	if err != nil {
		return
	}

	claims, ok := token.Claims.(*jwtClaims)

	if !ok {
		return nil, errors.New("jwt is exipired")
	}

	if claims.ExpiresAt < time.Now().Local().Unix() {
		return nil, errors.New("JWT is expired")
	}

	return claims, nil
}
