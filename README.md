# jwt
baa middleware for jwt.

## Example：
```
// Init 中间件初始化
func Init(b *baa.Baa) {
	//jwt 认证
	option := jwt.Config{
		CredentialsOptional: true,
		ExcludeUrls:         setting.Config.MustString("jwt.excludeUrls", ""),
	}

	b.Use(jwt.JWT(option))
}
```
## PS：

- 感谢 [go-jwt](https://github.com/dgrijalva/jwt-go),本中间件基于该包实现jwt验证。
- 该中间件尽量减少与本单位项目的耦合，无侵入，可以直接拿到自己项目中使用。
- 提供了丰富的config选项，可以根据实际业务场景配置。
