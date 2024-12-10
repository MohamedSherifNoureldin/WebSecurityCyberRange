package auth

import (
	"strings"

	"cyberrange/db"

	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
)

type ChangePassword struct {
	Email           string `json:"email"`
	Otp             string `json:"otp"`
	Password        string `json:"password"`
	ConfirmPassword string `json:"confirm_password"`
}

func ChangePass(c echo.Context) error {
	var changePassword ChangePassword

	// Bind and validate input
	err := c.Bind(&changePassword)
	if err != nil {
		return c.JSON(400, map[string]string{"error": "Invalid input"})
	}

	if changePassword.Email == "" || changePassword.Otp == "" || changePassword.Password == "" || changePassword.ConfirmPassword == "" {
		return c.JSON(400, map[string]string{"error": "All fields are required"})
	}

	if len(changePassword.Otp) != 3 {
		return c.JSON(400, map[string]string{"error": "Invalid OTP"})
	}

	if changePassword.Password != changePassword.ConfirmPassword {
		return c.JSON(400, map[string]string{"error": "Password and confirm password do not match"})
	}

	if len(changePassword.Password) < 8 {
		return c.JSON(400, map[string]string{"error": "Password must be at least 8 characters"})
	}

	changePassword.Email = strings.ToLower(changePassword.Email)

	// Check email and OTP in one query
	var otp string
	err = db.DB.QueryRow("SELECT otp FROM users WHERE email = ? AND otp = ?", changePassword.Email, changePassword.Otp).Scan(&otp)
	if err != nil {
		// Generic error message for both invalid email and OTP
		return c.JSON(401, map[string]string{"error": "Invalid email or OTP"})
	}

	// Hash the new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(changePassword.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to hash password"})
	}

	// Update the user's password
	_, err = db.DB.Exec("UPDATE users SET password = ? WHERE email = ?", hashedPassword, changePassword.Email)
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to update password"})
	}

	return c.JSON(200, map[string]string{"message": "Password updated successfully"})
}
