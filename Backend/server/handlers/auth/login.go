package auth

import (
	"os"
	"strings"
	"time"

	"cyberrange/db"
	"cyberrange/types"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"

	"golang.org/x/crypto/bcrypt"
)

func Login(c echo.Context) error {
	var user types.UserLogin
	if err := c.Bind(&user); err != nil {
		return c.JSON(400, map[string]string{"error": "Invalid input"})
	}

	// Validate input fields
	if user.EmailOrID == "" || user.Password == "" {
		return c.JSON(400, map[string]string{"error": "Please provide all required fields"})
	}

	user.EmailOrID = strings.ToLower(user.EmailOrID)

	// Fetch user details from the database
	var role, hashedPassword, name, email, user_id string
	query := "SELECT role, password, name, email, user_id FROM users WHERE (email = $1 OR user_id = $2)"
	err := db.DB.QueryRow(query, user.EmailOrID, user.EmailOrID).Scan(&role, &hashedPassword, &name, &email, &user_id)
	if err != nil {
		// Hide whether the issue is with the email/ID or password for security
		return c.JSON(401, map[string]string{"error": "Invalid credentials"})
	}

	// Validate the supplied password
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(user.Password))
	if err != nil {
		// Password mismatch
		return c.JSON(401, map[string]string{"error": "Invalid credentials"})
	}

	// Extract email prefix for token generation
	emailParts := strings.Split(email, "@")
	if len(emailParts) > 0 {
		email = emailParts[0]
	}

	// Generate JWT token
	token, err := generateToken(email, role, name, user_id)
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to generate token"})
	}

	// Respond with the generated token and user details
	return c.JSON(200, map[string]string{
		"token": token,
		"role":  role,
		"name":  name,
	})
}

func generateToken(id, role, name, user_id string) (string, error) {

	secretKey := []byte(os.Getenv("JWT_SECRET"))

	token, err := createToken(id, role, name, user_id, secretKey)
	if err != nil {
		return "", err
	}

	return token, nil
}

func createToken(id, role, name, user_id string, secretKey []byte) (string, error) {
	claims := jwt.MapClaims{}
	claims["id"] = id
	claims["role"] = role
	claims["name"] = name
	claims["user_id"] = user_id
	claims["iat"] = time.Now().Unix()
	claims["exp"] = time.Now().Add(time.Hour * 24 * 30).Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}
