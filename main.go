package main

import (
	"fmt"
	"os"

	"github.com/ashiqYousuf/GoJWTs/controllers"
	"github.com/ashiqYousuf/GoJWTs/initializers"
	"github.com/ashiqYousuf/GoJWTs/middlewares"
	"github.com/gin-gonic/gin"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectDB()
	// initializers.SyncDB()
}

func main() {
	router := gin.Default()

	router.POST("/signup", controllers.Signup)
	router.POST("/login", controllers.Login)
	router.GET("/users", middlewares.RequireAuth, controllers.GetUsers)

	router.Run(fmt.Sprintf("localhost:%v", os.Getenv("PORT")))
}
