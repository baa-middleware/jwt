package jwt

import (
	"fmt"
	"net/http"
	"strings"

	gojwt "github.com/dgrijalva/jwt-go"
	baa "gopkg.in/baa.v1"
)

// errorHandler 无论什么时候发生错误，该函数将被调用
// 如果返回 false 将 c.Break; 如果返回 true 将 c.Next
type errorHandler func(c *baa.Context, err error) bool

// TokenExtractor 获取jwt的token的方法，暂时实现了从header中获取
type tokenExtractor func(name string, c *baa.Context) (string, error)

// addonValidator 附加验证器
type addonValidator func(name string, c *baa.Context) error

// customValidator 自定义验证器
type customValidator func(c *baa.Context, config Config) error

//Config JWTMiddleware 认证的配置
type Config struct {
	// Name 配置token标识，默认为 Authorization
	Name string
	// Signing key to validate token
	SigningKey string
	// ErrorHandler 验证过程出现错误的处理方法，默认onError方法，可定制其他处理方式
	ErrorHandler errorHandler
	// Extractor 提取jwt凭证的方式，默认从header中获取，可定制为从cookie等获取
	Extractor tokenExtractor
	// EnableAuthOnOptions option 方法是否进行验证的开关 true 验证，false 不验证
	EnableAuthOnOptions bool
	// SigningMethod 加密方式
	SigningMethod gojwt.SigningMethod
	// ExcludeURL 配置不进行jwt验证的具体URL
	ExcludeURL []string
	// ExcludePrefix 配置不进行jwt验证的URL前缀
	ExcludePrefix []string
	// ContextKey Context key to store user information from the token into context.
	// Optional. Default value "user".
	ContextKey string
	//CustomValidator 自定义验证器
	CustomValidator customValidator
	//AddonValidator 附加验证器
	AddonValidator addonValidator

	//该配置项对外隐藏
	validationKeyGetter gojwt.Keyfunc
}

// onError 默认的认证过程出现错误的处理方式
// 如果返回 false 将 c.Break; 如果返回 true 将 c.Next
func onError(c *baa.Context, err error) bool {
	//认证授权失败
	c.Resp.WriteHeader(http.StatusUnauthorized)
	c.Resp.Write([]byte(err.Error()))
	return false
}

//FromAuthHeader 从request的header中获取凭证信息
func FromAuthHeader(name string, c *baa.Context) (string, error) {
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

//JWT json web token中间件注册到baa
func JWT(config Config) baa.HandlerFunc {
	if config.Name == "" {
		config.Name = "Authorization"
	}
	if config.ErrorHandler == nil {
		config.ErrorHandler = onError
	}
	if config.Extractor == nil {
		config.Extractor = FromAuthHeader
	}
	if config.SigningMethod == nil {
		config.SigningMethod = gojwt.SigningMethodHS256
	}
	if config.ContextKey == "" {
		config.ContextKey = "user"
	}

	if config.SigningKey == "" {
		panic("jwt middleware requires signing key")
	} else {
		config.validationKeyGetter = func(token *gojwt.Token) (interface{}, error) {
			return []byte(config.SigningKey), nil
		}
	}
	if config.CustomValidator == nil {
		config.CustomValidator = checkJWT
	}

	return func(c *baa.Context) {
		// 如果存在错误，即jwt检查token失败，则访问中断返回
		// 如果错误为nil 则说明验证通过，访问继续
		if err := config.CustomValidator(c, config); err != nil {
			if ret := config.ErrorHandler(c, err); ret == false {
				c.Break()
			}
		}
		c.Next()
	}
}

//按照规则检查token
func checkJWT(c *baa.Context, config Config) error {
	r := c.Req

	if !config.EnableAuthOnOptions {
		if r.Method == "OPTIONS" {
			return nil
		}
	}

	// 检查排除的URL
	if len(config.ExcludeURL) > 0 {
		for _, url := range config.ExcludeURL {
			if url == c.Req.URL.Path {
				return nil
			}
		}
	}
	if len(config.ExcludePrefix) > 0 {
		for _, prefix := range config.ExcludePrefix {
			if strings.HasPrefix(c.Req.URL.Path, prefix) {
				return nil
			}
		}
	}

	// 从request中按照初始化jwt中间件制定的方法获取token
	token, err := config.Extractor(config.Name, c)

	// 认证过程中出现任何错误，将调用制定的错误处理函数并且返回发生的错误
	if err != nil {
		return fmt.Errorf("Error extracting token: %v", err)
	}
	if token == "" {
		// 请求的凭证丢失
		return fmt.Errorf("Required authorization token not found")
	}

	// 按照算法解密token
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
	//将自定义信息提取出来放到baa的context中，避免多次解密
	claims := parsedToken.Claims.(gojwt.MapClaims)
	//将用户信息从token中获取，写到baa的context中
	c.Set(config.ContextKey, claims[config.ContextKey])

	//执行客户附加的验证
	if config.AddonValidator != nil {
		err := config.AddonValidator(config.Name, c)
		if err != nil {
			return fmt.Errorf("Custom validate is invalid")
		}
	}

	return nil
}
