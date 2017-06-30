// Package jwt implement jwt auth token validator for baa
package jwt

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	gojwt "github.com/dgrijalva/jwt-go"
	baa "gopkg.in/baa.v1"
)

// errorHandler handle error and return a bool value
// return false will break conext, return true will handle next context
type errorHandler func(c *baa.Context, err error) bool

// TokenExtractor extract jwt token
type tokenExtractor func(name string, c *baa.Context) (string, error)

// addonValidator addon validator, after jwt standard validator pass
type addonValidator func(name string, c *baa.Context) error

// customValidator jwt standard validator
type customValidator func(config *Config, c *baa.Context) error

// Provider JWT validator handler
type Provider struct {
	config *Config
}

//Config JWT Middleware config
type Config struct {
	// Name token name, default: Authorization
	Name string
	// Signing key to validate token
	SigningKey string
	// ErrorHandler validate error handler, default: defaultOnError
	ErrorHandler errorHandler
	// Extractor extract jwt token, default extract from header: defaultExtractorFromHeader
	Extractor tokenExtractor
	// EnableAuthOnOptions http option method validate switch
	EnableAuthOnOptions bool
	// SigningMethod sign method, default: HS256
	SigningMethod gojwt.SigningMethod
	// ExcludeURL exclude url will skip jwt validator
	ExcludeURL []string
	// ExcludePrefix exclude url prefix will skip jwt validator
	ExcludePrefix []string
	// ContextKey Context key to store user information from the token into context.
	// Optional. Default value "user".
	ContextKey string
	//AddonValidator addon validator will handle after standard validator
	AddonValidator addonValidator
	// CustomValidator custom validator suggestion flow：
	// 1. check exlude url, and exclude url prefix
	// 2. extract token string
	// 3. check token sign
	// 4. check token ttl
	// 5. save custom value to conext after check passed
	// 6. handle addon validator
	CustomValidator customValidator
	// validationKeyGetter
	validationKeyGetter gojwt.Keyfunc
}

// New create a JWT provider
func New(config *Config) *Provider {
	if config.Name == "" {
		config.Name = "Authorization"
	}
	if config.ContextKey == "" {
		config.ContextKey = config.Name
	}
	if config.ErrorHandler == nil {
		config.ErrorHandler = defaultOnError
	}
	if config.Extractor == nil {
		config.Extractor = defaultExtractorFromHeader
	}
	if config.SigningMethod == nil {
		config.SigningMethod = gojwt.SigningMethodHS256
	}

	if config.SigningKey == "" {
		panic("jwt middleware requires signing key")
	} else {
		config.validationKeyGetter = func(token *gojwt.Token) (interface{}, error) {
			return []byte(config.SigningKey), nil
		}
	}
	if config.CustomValidator == nil {
		config.CustomValidator = defaultCheckJWT
	}

	return &Provider{config}
}

// GeneratorToken generate token by custom value and token ttl
func (t *Provider) GeneratorToken(customValue string, ttl time.Duration) (string, error) {
	claims := make(gojwt.MapClaims)
	claims[t.config.ContextKey] = customValue
	claims["exp"] = time.Now().Add(ttl).Unix()
	token := gojwt.NewWithClaims(t.config.SigningMethod, claims)
	// sign token and get the complete encoded token as a string
	return token.SignedString([]byte(t.config.SigningKey))
}

// GetCustomValue return custom value in token, or returns error
func (t *Provider) GetCustomValue(c *baa.Context) (string, error) {
	val := c.Get(t.config.ContextKey)
	if val == nil {
		return "", fmt.Errorf("token value not exist")
	}
	return val.(string), nil
}

//JWT json web token for baa
func JWT(t *Provider) baa.HandlerFunc {
	return func(c *baa.Context) {
		if err := t.config.CustomValidator(t.config, c); err != nil {
			if ret := t.config.ErrorHandler(c, err); ret == false {
				c.Break()
			}
		}
		c.Next()
	}
}

// defaultOnError default error handler
// return false will break conext, return true will handle next context
func defaultOnError(c *baa.Context, err error) bool {
	c.Resp.WriteHeader(http.StatusUnauthorized)
	c.Resp.Write([]byte(err.Error()))
	return false
}

// defaultExtractorFromHeader extract token from header
func defaultExtractorFromHeader(name string, c *baa.Context) (string, error) {
	authHeader := c.Req.Header.Get(name)
	if authHeader == "" || len(authHeader) <= 7 {
		return "", nil // No error, just no token
	}
	// TODO: Make this a bit more robust, parsing-wise
	authHeaderParts := strings.Split(authHeader, " ")
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "bearer" {
		return "", fmt.Errorf("Authorization header format must be Bearer {token}")
	}

	return authHeaderParts[1], nil
}

// defaultCheckJWT execlude token check flow, or returns error
// 1. check exlude url, and exclude url prefix
// 2. extract token string
// 3. check token sign
// 4. check token ttl
// 5. save custom value to conext after check passed
// 6. handle addon validator
func defaultCheckJWT(config *Config, c *baa.Context) error {
	r := c.Req

	if !config.EnableAuthOnOptions {
		if r.Method == "OPTIONS" {
			return nil
		}
	}

	// check exclude url
	if len(config.ExcludeURL) > 0 {
		for _, url := range config.ExcludeURL {
			if url == c.Req.URL.Path {
				c.Set("JwtSkip", true)
				return nil
			}
		}
	}
	// check exclude url prefix
	if len(config.ExcludePrefix) > 0 {
		for _, prefix := range config.ExcludePrefix {
			if strings.HasPrefix(c.Req.URL.Path, prefix) {
				c.Set("JwtSkip", true)
				return nil
			}
		}
	}

	// extract token
	token, err := config.Extractor(config.Name, c)

	if err != nil {
		return fmt.Errorf("Error extracting token: %v", err)
	}
	if token == "" {
		// no token
		return fmt.Errorf("Required authorization token not found")
	}

	// parse token value
	parsedToken, err := gojwt.Parse(token, config.validationKeyGetter)

	if err != nil {
		return fmt.Errorf("Error parsing token: %v", err)
	}

	if config.SigningMethod != nil && config.SigningMethod.Alg() != parsedToken.Header["alg"] {
		message := fmt.Sprintf("Expected %s signing method but token specified %s",
			config.SigningMethod.Alg(),
			parsedToken.Header["alg"])
		return fmt.Errorf("Error validating token algorithm: %s", message)
	}

	if !parsedToken.Valid {
		return fmt.Errorf("Token is invalid")
	}
	// save custom value to context
	claims := parsedToken.Claims.(gojwt.MapClaims)
	c.Set(config.ContextKey, claims[config.ContextKey])

	// handle addon validator
	if config.AddonValidator != nil {
		err := config.AddonValidator(config.Name, c)
		if err != nil {
			return fmt.Errorf("JWT Addon validate check failed: %s", err)
		}
	}

	return nil
}
