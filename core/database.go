package core

import (
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func OpenDatabase(dbDsn string) (*gorm.DB, error) {
	// use postgres
	var DB *gorm.DB
	var err error

	if dbDsn[:8] == "postgres" {
		DB, err = gorm.Open(postgres.Open(dbDsn), &gorm.Config{
			Logger: logger.Default.LogMode(logger.Silent),
		})
	} else {
		DB, err = gorm.Open(sqlite.Open(dbDsn), &gorm.Config{
			Logger: logger.Default.LogMode(logger.Silent),
		})
	}

	// generate new models.
	ConfigureModels(DB) // create models.

	if err != nil {
		return nil, err
	}
	return DB, nil
}

func ConfigureModels(db *gorm.DB) {
	db.AutoMigrate(&AuthToken{}, &User{})
}
