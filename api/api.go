package api

import (
	"auth-svc/core"
	"fmt"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
	"net/http"
)

var (
	auth *core.AuthorizationServer
)

func NewApiService(db *gorm.DB) {
	auth = core.Init()
	auth = auth.SetDB(db)
}

func InitRouter(e *echo.Echo) {
	e.POST("/check-api-key", BasicUserApiCheckHandler)
	e.POST("/check-user-api-key", BasicApiUserCheckHandler)
	e.POST("/check-user-pass", BasicUserPassHandler)

	e.POST("/generate-nonce", GenerateNonceHandler)
	e.POST("/login-with-metamask", LoginWithMetamaskHandler)
	e.POST("/register-with-metamask", RegisterWithMetamaskHandler)
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
		return err
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
		return err
	}
	return c.JSON(http.StatusOK, result)
}

func RegisterWithMetamaskHandler(c echo.Context) error {
	var result core.MetamaskLoginResult

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
