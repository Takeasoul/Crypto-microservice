package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID            int
	Username      string
	Password      string
	UniqueUserKey string
}

type ErrorResponse struct {
	Message string `json:"error"`
}

type SuccessResponse struct {
	Message string `json:"message"`
}

type UserResponse struct {
	Username      string `json:"username"`
	UniqueUserKey string `json:"unique_user_key"`
}

var uniqueKeys = make(map[string]bool)

func isUniqueKey(key string) bool {
	_, ok := uniqueKeys[key]
	return !ok
}

func generateUniqueKey() (string, error) {
	for {
		key := uuid.New().String()
		if isUniqueKey(key) {
			uniqueKeys[key] = true
			return key, nil
		}
	}
}

// Функция для отправки HTTP POST запроса
func sendHTTPPostRequest(url string, requestData interface{}, responseData interface{}) error {
	client := &http.Client{}
	requestBody, err := json.Marshal(requestData)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(requestBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP request failed with status code %d: %s", resp.StatusCode, string(responseBody))
	}

	if responseData != nil {
		if err := json.Unmarshal(responseBody, &responseData); err != nil {
			return err
		}
	}

	return nil
}

func main() {

	// Подключение к базе данных PostgreSQL
	db, err := sql.Open("postgres", "host=localhost port=5432 user=postgres password=89818286905Niki dbname=postgres sslmode=disable options='-c client_encoding=utf8'")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Инициализация маршрутизатора Gin
	router := gin.Default()

	// Обработчик для регистрации пользователя
	// Обработчик для регистрации пользователя
	router.POST("/register", func(c *gin.Context) {
		var user User
		UniqueUserKey, err := generateUniqueKey()
		user.UniqueUserKey = UniqueUserKey
		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, ErrorResponse{Message: err.Error()})
			return
		}

		log.Printf("Received registration request - username: %s, password: %s, UniqueUserKey: %s", user.Username, user.Password, user.UniqueUserKey)

		// Проверка уникальности имени пользователя
		var count int
		err = db.QueryRow("SELECT COUNT(*) FROM users WHERE username = $1", user.Username).Scan(&count)
		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{Message: err.Error()})
			return
		}
		if count > 0 {
			c.Header("Content-Type", "application/json")
			c.JSON(http.StatusBadRequest, ErrorResponse{Message: "Username already exists"})
			return
		}

		// Хэширование пароля
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			c.Header("Content-Type", "application/json")
			c.JSON(http.StatusInternalServerError, ErrorResponse{Message: err.Error()})
			return
		}

		// Вставка пользователя в базу данных
		_, err = db.Exec("INSERT INTO users (username, password, uniqueuserkey) VALUES ($1, $2, $3)", user.Username, string(hashedPassword), user.UniqueUserKey)
		if err != nil {
			c.Header("Content-Type", "application/json")
			c.JSON(http.StatusInternalServerError, ErrorResponse{Message: err.Error()})
			log.Println(err)
			return
		}

		// HTTP запрос для создания нового кошелька
		walletRequest := gin.H{
			"uniqueUserKey": user.UniqueUserKey,
		}
		walletResponse := make(map[string]interface{})
		if err := sendHTTPPostRequest("http://192.168.0.103:8081/wallets", walletRequest, &walletResponse); err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{Message: err.Error()})
			log.Println(err)
			return
		}

		// Ваш код для обработки ответа создания кошелька

		c.JSON(http.StatusOK, SuccessResponse{Message: "User registered successfully"})
	})

	// Обработчик для логина пользователя
	router.POST("/login", func(c *gin.Context) {
		var user User
		if err := c.ShouldBindJSON(&user); err != nil {
			// Проверка типа ошибки
			if e, ok := err.(*gin.Error); ok && e.Err != nil {
				// Ошибка 400 - неверный запрос
				c.JSON(http.StatusBadRequest, ErrorResponse{Message: e.Err.Error()})
				return
			}
			// Ошибка при привязке JSON
			c.JSON(http.StatusBadRequest, ErrorResponse{Message: err.Error()})
			return
		}

		log.Println("Received login request - username:", user.Username, "password:", user.Password)

		// Проверка наличия пользователя в базе данных
		var savedPassword string
		err := db.QueryRow("SELECT password FROM users WHERE username = $1", user.Username).Scan(&savedPassword)
		if err != nil {
			c.Header("Content-Type", "application/json")
			c.JSON(http.StatusUnauthorized, ErrorResponse{Message: "Username is not exist"})
			return
		}

		// Сравнение хэшированного пароля
		err = bcrypt.CompareHashAndPassword([]byte(savedPassword), []byte(user.Password))
		if err != nil {
			c.Header("Content-Type", "application/json")
			c.JSON(http.StatusUnauthorized, ErrorResponse{Message: "Invalid username or password"})
			return
		}

		// Получение уникального ключа пользователя
		var uniqueUserKey string
		err = db.QueryRow("SELECT uniqueuserkey FROM users WHERE username = $1", user.Username).Scan(&uniqueUserKey)
		if err != nil {
			c.Header("Content-Type", "application/json")
			c.JSON(http.StatusInternalServerError, ErrorResponse{Message: err.Error()})
			return
		}

		// Формирование ответа с данными пользователя
		userResponse := UserResponse{
			Username:      user.Username,
			UniqueUserKey: uniqueUserKey,
		}

		c.JSON(http.StatusOK, userResponse)
	})
	// Запуск сервера на порту 8080
	if err := router.Run("192.168.0.103:8080"); err != nil {
		log.Fatal(err)

	}
}
