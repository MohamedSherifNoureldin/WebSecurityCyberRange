package auth

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

	"cyberrange/db"

	"github.com/labstack/echo/v4"
)

type ForgetPassword struct {
	Email string `json:"email"`
}

func ForgetP(c echo.Context) error {
	var forgetPassword ForgetPassword

	err := c.Bind(&forgetPassword)
	if err != nil {
		// Return a generic error message
		return c.JSON(400, map[string]string{"error": "Invalid input"})
	}

	if forgetPassword.Email == "" {
		return c.JSON(400, map[string]string{"error": "Please provide the email"})
	}

	forgetPassword.Email = strings.ToLower(forgetPassword.Email)

	otp := generateOTP()

	// Use a single update query to update the OTP if the email exists
	result, err := db.DB.Exec("UPDATE users SET otp = ? WHERE email = ?", otp, forgetPassword.Email)
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Internal server error"})
	}

	// Check if any row was affected
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Internal server error"})
	}

	// Always return the same response regardless of whether the email exists
	if rowsAffected == 0 {
		// Simulate a successful response even if the email doesn't exist
		return c.JSON(200, map[string]string{"message": "Check your email for OTP to reset your password"})
	}

	// Simulate sending OTP email here (log for testing or send via email service)

	return c.JSON(200, map[string]string{"message": "Check your email for OTP to reset your password"})
}

func generateOTP() string {
	rand.Seed(time.Now().UnixNano())

	otp := rand.Intn(900) + 100

	return fmt.Sprintf("%03d", otp)
}
