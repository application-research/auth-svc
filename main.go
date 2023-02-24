package main

import (
	"go-micro.dev/v4/registry"
	"go-micro.dev/v4/server"
	"log"
	"net/http"

	httpServer "github.com/go-micro/plugins/v4/server/http"
	"go-micro.dev/v4"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

var (
	service = "auth-svc"
	version = "latest"
)

func main() {
	// Create service
	srv := httpServer.NewServer(
		server.Name(service),
		server.Version(version),
		server.Address(":1313"),
	)

	// Echo instance
	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())

	authService := newAuthService()
	authService.InitRouter(e)

	hd := srv.NewHandler(e)
	if err := srv.Handle(hd); err != nil {
		log.Fatalln(err)
	}

	service := micro.NewService(
		micro.Server(srv),
		micro.Registry(registry.NewRegistry()),
	)
	service.Init()
	service.Run()
}

type authService struct{}

func newAuthService() *authService {
	return &authService{}
}

func (a *authService) InitRouter(e *echo.Echo) {
	e.POST("/check-api-key", a.BasicUserApiCheckHandler)
	e.POST("/check-user-api-key", a.BasicApiUserCheckHandler)
	e.POST("/check-user-pass", a.BasicUserPassHandler)
}

func (a *authService) BasicUserApiCheckHandler(c echo.Context) error {
	return c.NoContent(http.StatusOK)
}

func (a *authService) BasicApiUserCheckHandler(c echo.Context) error {
	return c.NoContent(http.StatusOK)
}

func (a *authService) BasicUserPassHandler(c echo.Context) error {
	return c.NoContent(http.StatusOK)
}
