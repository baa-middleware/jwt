package jwt

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	gojwt "github.com/dgrijalva/jwt-go"
	baa "gopkg.in/baa.v1"
)

// errorHandler 无论什么时候发生错误，该函数将被调用
// 如果返回 false 将 c.Break; 如果返回 true 将 c.Next
type errorHandler func(c *baa.Context, err error) bool

// TokenExtractor 获取jwt的token的方法，暂时实现了从header中获取
type tokenExtractor func(name string, c *baa.Context) (string, error)

// addonValidator 附加验证器, jwt验证通过后执行
type addonValidator func(name string, c *baa.Context) error

// customValidator 自定义验证器，如果设置了将不使用默认的jwt校验
type customValidator func(c *baa.Context, config *Config) error

// Provider JWT生成和验证提供者
type Provider struct {
	config *Config
}

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
	//AddonValidator 附加验证器
	AddonValidator addonValidator
	// CustomValidator 自定义验证器，建议执行过程：
	// 1. 检查是否是要排除的URL
	// 2. 检查是否传递了token
	// 3. 检查token是否可以正常解密
	// 4. 检查token是否过期
	// 5. 检查通过，保存customValue到context中
	// 6. 执行附加检查
	CustomValidator customValidator

	//该配置项对外隐藏
	validationKeyGetter gojwt.Keyfunc
}

// New 创建一个新的JWT生成和验证对象
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

// GeneratorToken 生成token，传入token中要存储的数据和有效期
func (t *Provider) GeneratorToken(customValue string, ttl time.Duration) (string, error) {
	claims := make(gojwt.MapClaims)
	claims[t.config.ContextKey] = customValue
	claims["exp"] = time.Now().Add(ttl).Unix()
	token := gojwt.NewWithClaims(t.config.SigningMethod, claims)
	// 使用自定义字符串加密 and get the complete encoded token as a string
	return token.SignedString([]byte(t.config.SigningKey))
}

// GetCustomValue 返回token中存储的数据，如果token验证失败返回错误
func (t *Provider) GetCustomValue(c *baa.Context) (string, error) {
	val := c.Get(t.config.ContextKey)
	if val == nil {
		return "", fmt.Errorf("token value not exist")
	}
	return val.(string), nil
}

//JWT json web token中间件注册到baa
func JWT(t *Provider) baa.HandlerFunc {
	return func(c *baa.Context) {
		// 如果存在错误，即jwt检查token失败，则访问中断返回
		// 如果错误为nil 则说明验证通过，访问继续
		if err := t.config.CustomValidator(c, t.config); err != nil {
			if ret := t.config.ErrorHandler(c, err); ret == false {
				c.Break()
			}
		}
		c.Next()
	}
}

// defaultOnError 默认的认证过程出现错误的处理方式
// 如果返回 false 将 c.Break; 如果返回 true 将 c.Next
func defaultOnError(c *baa.Context, err error) bool {
	//认证授权失败
	c.Resp.WriteHeader(http.StatusUnauthorized)
	c.Resp.Write([]byte(err.Error()))
	return false
}

// defaultExtractorFromHeader 从request的header中获取凭证信息
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

// defaultCheckJWT 按照规则检查token 如果出错，返回错误
// 1. 检查是否是要排除的URL
// 2. 检查是否传递了token
// 3. 检查token是否可以正常解密
// 4. 检查token是否过期
// 5. 检查通过，保存customValue到context中
// 6. 执行附加检查
func defaultCheckJWT(c *baa.Context, config *Config) error {
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
			return fmt.Errorf("JWT Addon validate check failed: %s", err)
		}
	}

	return nil
}
