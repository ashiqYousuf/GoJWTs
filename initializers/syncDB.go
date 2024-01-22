package initializers

import (
	"github.com/ashiqYousuf/GoJWTs/models"
)

func SyncDB() {
	DB.AutoMigrate(&models.User{})
}
