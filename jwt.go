package jwt

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	gojwt "github.com/dgrijalva/jwt-go"
	baa "gopkg.in/baa.v1"
)

//无论什么时候发生错误，该函数将被调用
type errorHandler func(c *baa.Context, err string)

//TokenExtractor 获取jwt的token的方法，暂时实现了从header中获取
type tokenExtractor func(c *baa.Context) (string, error)

//Config JWTMiddleware 认证的配置
type Config struct {
	//Signing key to validate token
	SigningKey string
	//验证过程出现错误的处理方法，默认onError方法，可定制其他处理方式
	ErrorHandler errorHandler
	//该配置项 是是否对访问进行接口认证的开关 true 验证
	CredentialsOptional bool
	//提取jwt凭证的方式，默认从header中获取，可定制为从cookie等获取
	Extractor tokenExtractor
	//option 方法是否进行验证的开关 true 验证，false 不验证
	EnableAuthOnOptions bool
	//加密方式
	SigningMethod gojwt.SigningMethod
	//该配置项配置不进行jwt验证的路由，若多个，逗号分隔。比如登录和注册。
	ExcludeRouteName string
	//Context key to store user information from the token into context.
	// Optional. Default value "user".
	ContextKey string

	//该配置项对外隐藏
	validationKeyGetter gojwt.Keyfunc
}

// 默认的认证过程出现错误的处理方式
func onError(c *baa.Context, err string) {
	//认证授权失败
	c.Resp.WriteHeader(http.StatusUnauthorized)
	c.Resp.Write([]byte(err))
}

//FromAuthHeader 从request的header中获取凭证信息
func FromAuthHeader(c *baa.Context) (string, error) {
	authHeader := c.Req.Header.Get("Authorization")
	if authHeader == "" {
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

	return func(c *baa.Context) {
		err := checkJWT(c, config)

		// 如果存在错误，即jwt检查token失败，则访问中断返回
		//如果错误为nil 则说明验证通过，访问继续
		if err == nil {
			c.Next()
		}
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

	//如果访问的url在排除urls中则不做jwt验证，直接next
	if len(config.ExcludeRouteName) > 0 {
		urls := strings.Split(config.ExcludeRouteName, ",")
		requestURL := c.RouteName()
		for _, url := range urls {
			url = strings.ToLower(strings.Trim(url, " \t\r\n"))
			if strings.EqualFold(url, requestURL) {
				return nil
			}
		}
	}

	// 从request中按照初始化jwt中间件制定的方法获取token
	token, err := config.Extractor(c)

	// 认证过程中出现任何错误，将调用制定的错误处理函数并且返回发生的错误
	if err != nil {
		config.ErrorHandler(c, err.Error())
		return fmt.Errorf("Error extracting token: %v", err)
	}
	if token == "" {
		if !config.CredentialsOptional {
			// 没有设置凭证要求，仅仅是没有凭证
			return nil
		}

		// 设置了认证选项（CredentialsOptional）, 请求的凭证丢失
		errorMsg := "Required authorization token not found"
		config.ErrorHandler(c, errorMsg)
		return fmt.Errorf(errorMsg)
	}

	// 按照算法解密token
	parsedToken, err := gojwt.Parse(token, config.validationKeyGetter)

	if err != nil {
		config.ErrorHandler(c, err.Error())
		return fmt.Errorf("Error parsing token: %v", err)
	}

	if config.SigningMethod != nil && config.SigningMethod.Alg() != parsedToken.Header["alg"] {
		message := fmt.Sprintf("Expected %s signing method but token specified %s",
			config.SigningMethod.Alg(),
			parsedToken.Header["alg"])v
		config.ErrorHandler(c, errors.New(message).Error())
		return fmt.Errorf("Error validating token algorithm: %s", message)
	}

	if !parsedToken.Valid {
		config.ErrorHandler(c, "The token isn't valid")
		return fmt.Errorf("Token is invalid")
	}
	//将user_id和用户权限提取出来放到baa的context中，避免多次解密
	claims := parsedToken.Claims.(gojwt.MapClaims)
	//将用户信息从token中获取，写到baa的context中
	c.Set(config.ContextKey, claims[config.ContextKey])

	return nil
}
