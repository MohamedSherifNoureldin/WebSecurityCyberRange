package auth

import (
	"crypto/rand"
	"fmt"
	"math/big"
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
		return c.JSON(400, map[string]string{"error": "Invalid request payload"})
	}

	if forgetPassword.Email == "" {
		return c.JSON(400, map[string]string{"error": "Please provide the email"})
	}

	forgetPassword.Email = strings.ToLower(forgetPassword.Email)

	var email string
	err = db.DB.QueryRow("SELECT email FROM users WHERE email = ?", forgetPassword.Email).Scan(&email)
	if err != nil {
		return c.JSON(200, map[string]string{"message": "If the email exists, you will receive an OTP"})
	}

	// Generate a secure OTP
	otp, otpErr := generateSecureOTP(6)
	if otpErr != nil {
		return c.JSON(500, map[string]string{"error": "Failed to generate OTP"})
	}

	// Update the OTP and set its expiration time (5 minutes from now)
	expiration := time.Now().Add(5 * time.Minute)
	_, err = db.DB.Exec("UPDATE users SET otp = ?, otp_expiration = ? WHERE email = ?", otp, expiration, forgetPassword.Email)
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to update OTP"})
	}

	return c.JSON(200, map[string]string{"message": "If the email exists, you will receive an OTP"})
}

// generateSecureOTP generates a cryptographically secure OTP of the specified length
func generateSecureOTP(length int) (string, error) {
	otp := ""
	for i := 0; i < length; i++ {
		// Generate a single random digit (0-9)
		num, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", fmt.Errorf("failed to generate OTP: %v", err)
		}
		otp += fmt.Sprintf("%d", num.Int64())
	}
	return otp, nil
}
