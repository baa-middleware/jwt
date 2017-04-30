# jwt
baa middleware for jwt.

## 使用：
```
// Init 中间件初始化
func Init(b *baa.Baa) {
	option := jwt.Config{
		SigningKey:          "vodjk.com",
		CredentialsOptional: true,
		ExcludeName:         []string{"/login", "/verifycode"},
	}

	b.Use(jwt.JWT(option))
}
```
## 配置：

### Name `string`

jwt token在header头中的标识，默认为 `Authorization`

### SigningKey `string`

验证token使用的签名字符串

### ErrorHandler `func(c *baa.Context, err string)`

验证token过程中出现错误执行的操作， 如用户不设置则默认访问返回401未授权

### CredentialsOptional `bool`

是否对访问进行接口认证的开关 ,true 验证 false 不验证。多用于在测试环境中，该配置设置为false，则可以不进行jwt认证，专注于业务的实现。默认为false

### Extractor `func(name string, c *baa.Context) (string, error)`

提取jwt凭证的方式，默认从header中获取，可定制为从cookie等获取，`name`参数是提取token的标识

### EnableAuthOnOptions `bool`

option 方法是否进行验证的开关 true 验证，false 不验证，默认为false

### SigningMethod `gojwt.SigningMethod`

加密算法,默认为:SigningMethodHS256

### ExcludeURL `[]string`

配置不进行jwt验证的URL，比如登录和注册, /login,/register

### ExcludePrefix `[]string`

配置不进行jwt验证的URL前缀，比如所有public目录下的资源无需验证,格式为/public

### ContextKey 

jwt验证通过后，将解密后的token信息存储在baa.Context中，存储用户自定义信息使用的key, 默认为 user

## PS：

- 感谢 [go-jwt](https://github.com/dgrijalva/jwt-go),本中间件基于该包实现jwt验证。
- 该中间件尽量减少与本单位项目的耦合，无侵入，可以直接拿到自己项目中使用。
- 提供了丰富的config选项，可以根据实际业务场景配置。
