package api

import (
	"auth-svc/core"
	"fmt"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
	"net/http"
	"time"
)

var (
	auth *core.AuthorizationServer
)

func NewApiService(db *gorm.DB) {
	auth = core.Init()
	auth = auth.SetDB(db)
}

const (
	PermLevelUpload = 1
	PermLevelUser   = 2
	PermLevelAdmin  = 10
)

func InitRouter(e *echo.Echo) {

	check := e.Group("/check")
	check.POST("/api-key", BasicUserApiCheckHandler)
	check.POST("/user-api-key", BasicApiUserCheckHandler)
	check.POST("/user-pass", BasicUserPassHandler)

	register := e.Group("/register")
	register.GET("/new-user", BasicRegisterTokenHandler)
	register.GET("/new-token/:userId", BasicRegisterTokenHandler)
	register.GET("/new-exp-token/:userId", BasicRegisterExpiringUserHandler)

	e.POST("/generate-nonce", GenerateNonceHandler)
	e.POST("/login-with-metamask", LoginWithMetamaskHandler)
	e.POST("/register-with-metamask", RegisterWithMetamaskHandler)

	user := e.Group("/user")
	user.Use(auth.AuthRequired(PermLevelUser))
	user.POST("/auth-address", withUser(AddAuthAddressHandler))
	user.DELETE("/auth-address", withUser(RemoveAuthAddressHandler))
	user.GET("/auth-address", withUser(GetAuthAddressHandler))

	// health check
	health := e.Group("/health")
	ConfigureHealthCheckRouter(health)
	// metrics
	ConfigMetricsRouter(e.Group("/metrics"))
}

func withUser(f func(echo.Context, *core.User) error) func(echo.Context) error {
	return func(c echo.Context) error {
		u, ok := c.Get("user").(*core.User)
		if !ok {
			return &core.HttpError{
				Code:    http.StatusUnauthorized,
				Reason:  core.ERR_INVALID_AUTH,
				Details: "endpoint not called with proper authentication",
			}
		}
		return f(c, u)
	}
}

func BasicRegisterTokenHandler(c echo.Context) error {
	result, _ := auth.NewUserAndAuthToken(c, 0)
	return c.JSON(http.StatusOK, map[string]interface{}{
		"token":   result.Token,
		"expires": result.Expiry,
	})

}

// BasicRegisterExpiringUserHandler // such as "300ms", "-1.5h" or "2h45m".
// // Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
func BasicRegisterExpiringUserHandler(c echo.Context) error {
	duration := c.Param("duration")
	fmt.Print(duration)
	durationToParse, err := time.ParseDuration(duration)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"error": "invalid duration",
		})
	}
	result, _ := auth.NewUserAndAuthToken(c, durationToParse)
	return c.JSON(http.StatusOK, map[string]interface{}{
		"token":   result.Token,
		"expires": result.Expiry,
	})

}

func GenerateNonceHandler(c echo.Context) error {
	var nonceParams core.NonceParams
	if err := c.Bind(&nonceParams); err != nil {
		return err
	}

	if nonceParams.Address == "" {
		return &core.HttpError{
			Code:    http.StatusUnprocessableEntity,
			Reason:  core.ERR_CONTENT_NOT_FOUND,
			Details: fmt.Sprintf("address paramater is required"),
		}
	}

	result, err := auth.GenerateNonce(nonceParams)
	if err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}
	return c.JSON(http.StatusOK, result)
}

func LoginWithMetamaskHandler(c echo.Context) error {
	var params core.MetamaskLoginParams
	if err := c.Bind(&params); err != nil {
		return err
	}

	if params.Address == "" || params.Signature == "" {
		return &core.HttpError{
			Code:    http.StatusUnprocessableEntity,
			Reason:  core.ERR_CONTENT_NOT_FOUND,
			Details: fmt.Sprintf("address and signature paramater is required"),
		}
	}

	result, err := auth.LoginWithMetamask(params)
	if err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}
	return c.JSON(http.StatusOK, result)
}

func AddAuthAddressHandler(c echo.Context, u *core.User) error {
	var params core.AuthAddressParams

	if err := c.Bind(&params); err != nil {
		return err
	}

	if params.Address == "" {
		return &core.HttpError{
			Code:    http.StatusUnprocessableEntity,
			Reason:  core.ERR_CONTENT_NOT_FOUND,
			Details: fmt.Sprintf("address paramater is required"),
		}
	}

	result, err := auth.AddAuthAddress(params, u)
	if err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}
	return c.JSON(http.StatusOK, result)
}

func RemoveAuthAddressHandler(c echo.Context, u *core.User) error {
	var params core.AuthAddressParams

	if err := c.Bind(&params); err != nil {
		return err
	}

	if params.Address == "" {
		return &core.HttpError{
			Code:    http.StatusUnprocessableEntity,
			Reason:  core.ERR_CONTENT_NOT_FOUND,
			Details: fmt.Sprintf("address paramater is required"),
		}
	}

	result, err := auth.RemoveAuthAddress(params, u)
	if err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}
	return c.JSON(http.StatusOK, result)
}

func GetAuthAddressHandler(c echo.Context, u *core.User) error {
	result, err := auth.GetAuthAddress(u)
	if err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}
	return c.JSON(http.StatusOK, result)
}

func RegisterWithMetamaskHandler(c echo.Context) error {
	var params core.RegisterWithMetamaskParams

	if err := c.Bind(&params); err != nil {
		return err
	}

	if params.Address == "" || params.InviteCode == "" {
		return &core.HttpError{
			Code:    http.StatusUnprocessableEntity,
			Reason:  core.ERR_CONTENT_NOT_FOUND,
			Details: fmt.Sprintf("address and invite code paramater is required"),
		}
	}

	result, err := auth.RegisterWithMetamask(params)
	if err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}
	return c.JSON(http.StatusOK, result)
}

func BasicUserApiCheckHandler(c echo.Context) error {
	var apiKeyParam core.ApiKeyParam
	if err := c.Bind(&apiKeyParam); err != nil {
		return err
	}
	result := auth.AuthenticateApiKey(apiKeyParam)
	return c.JSON(http.StatusOK, result)
}

func BasicApiUserCheckHandler(c echo.Context) error {
	var apiKeyParam core.ApiKeyParam
	if err := c.Bind(&apiKeyParam); err != nil {
		return err
	}
	result := auth.AuthenticateApiKeyUser(apiKeyParam)
	return c.JSON(http.StatusOK, result)
}

func BasicUserPassHandler(c echo.Context) error {
	var authParam core.AuthenticationParam
	if err := c.Bind(&authParam); err != nil {
		return err
	}

	result := auth.AuthenticateUserPassword(authParam)
	return c.JSON(http.StatusOK, result)
}
