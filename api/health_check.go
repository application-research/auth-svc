package api

import (
	"github.com/labstack/echo/v4"
	"net/http"
)

// ConfigureHealthCheckRouter > ConfigureHealthCheckRouter is a function that takes a pointer to an echo.Group and a pointer to a DeltaNode and
// returns nothing
func ConfigureHealthCheckRouter(healthCheckApiGroup *echo.Group) {
	//	health check api withouth auth
	healthCheckApiGroup.GET("/ping", func(c echo.Context) error {
		return c.String(http.StatusOK, "pong")
	})

}
