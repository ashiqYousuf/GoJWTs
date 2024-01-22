package controllers

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/ashiqYousuf/GoJWTs/initializers"
	"github.com/ashiqYousuf/GoJWTs/models"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func Signup(c *gin.Context) {
	var user models.User

	if err := c.Bind(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	user.Password = string(hash)

	tx := initializers.DB.Create(&user)

	if tx.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   tx.Error.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"data": gin.H{
			"user": user,
		},
	})
}

func Login(c *gin.Context) {
	var user models.User

	if err := c.Bind(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	var dbUser models.User
	initializers.DB.First(&dbUser, "email = ?", user.Email)

	if dbUser.ID == 0 {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "invalid email or password",
		})
		return
	}

	err := bcrypt.CompareHashAndPassword([]byte(dbUser.Password), []byte(user.Password))

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "invalid email or password",
		})
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":  dbUser.ID,
		"exp": time.Now().Add(time.Minute * 10).Unix(),
	})

	// ?Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))

	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "failed to create token",
		})
		return
	}

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("token", tokenString, 60*10, "", "", true, true)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"user": dbUser,
		},
	})
}

// ! This is a Protected Route

func GetUsers(c *gin.Context) {
	requestUser, exists := c.Get("user")

	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Something went wrong",
		})
	}

	fmt.Printf("\nrequest.user:- %#v\n", requestUser.(models.User))

	var users []models.User

	initializers.DB.Find(&users)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"results": len(users),
		"data": gin.H{
			"users": users,
		},
	})
}
