package main

import (
	"auth-svc/core"
	httpServer "github.com/go-micro/plugins/v4/server/http"
	"github.com/spf13/viper"
	"go-micro.dev/v4"
	"go-micro.dev/v4/registry"
	"go-micro.dev/v4/server"
	"gorm.io/gorm"
	"log"
	"time"

	"auth-svc/api"
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

	db := initDB()
	api.NewApiService(db)
	api.InitRouter(e)

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

func initDB() *gorm.DB {
	viper.SetConfigFile(".env")
	err := viper.ReadInConfig()
	dsn := viper.Get("DB_DSN").(string)

	db, err := core.OpenDatabase(dsn)
	sqldb, err := db.DB()
	if err != nil {
		panic(err)
	}
	sqldb.SetMaxIdleConns(80)
	sqldb.SetMaxOpenConns(250)
	sqldb.SetConnMaxIdleTime(time.Hour)
	sqldb.SetConnMaxLifetime(time.Second * 60)
	if err != nil {
		panic("failed to connect database")
	}

	return db
}
