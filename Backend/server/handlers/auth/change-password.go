package auth

import (
	"database/sql"
	"strings"

	"cyberrange/db"

	"fmt"
	"time"

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

	err := c.Bind(&changePassword)
	if err != nil {
		return c.JSON(400, map[string]string{"error": err.Error()})
	}

	if changePassword.Email == "" {
		fmt.Println("Please provide the email")
		return c.JSON(400, map[string]string{"error": "Please provide the email"})
	}

	if changePassword.Otp == "" {
		return c.JSON(400, map[string]string{"error": "Please provide the OTP"})
	}

	if len(changePassword.Otp) != 6 {
		return c.JSON(400, map[string]string{"error": "Invalid OTP"})
	}

	if changePassword.Password == "" {
		return c.JSON(400, map[string]string{"error": "Please provide the password"})
	}

	if changePassword.ConfirmPassword == "" {
		return c.JSON(400, map[string]string{"error": "Please provide the confirm password"})
	}

	if changePassword.Password != changePassword.ConfirmPassword {
		return c.JSON(400, map[string]string{"error": "Password and confirm password do not match"})
	}

	changePassword.Email = strings.ToLower(changePassword.Email)

	if len(changePassword.Password) < 8 {
		fmt.Println("Password must be at least 8 characters")
		// print for debugging
		return c.JSON(400, map[string]string{"error": "Password must be at least 8 characters"})
	}

	var email string

	err = db.DB.QueryRow("SELECT email FROM users WHERE email = ?", changePassword.Email).Scan(&email)
	if err != nil {
		return c.JSON(401, map[string]string{"error": "User not found"})
	}

	var otp sql.NullString
	var otpExpiry sql.NullTime

	err = db.DB.QueryRow("SELECT otp, otp_expiration FROM users WHERE email = ?", changePassword.Email).Scan(&otp, &otpExpiry)
	if err != nil {
		if err == sql.ErrNoRows {
			return c.JSON(401, map[string]string{"error": "Invalid OTP"})
		}
		return c.JSON(500, map[string]string{"error": "Database query error"})
	}
	// Check if OTP or OTP expiry is NULL
	if !otp.Valid || !otpExpiry.Valid {
		return c.JSON(401, map[string]string{"error": "Invalid OTP or OTP has expired"})
	}

	// Check if OTP has expired
	if time.Now().After(otpExpiry.Time) {
		return c.JSON(401, map[string]string{"error": "OTP has expired"})
	}

	// Check if OTP matches
	if otp.String != changePassword.Otp {
		return c.JSON(401, map[string]string{"error": "Incorrect OTP"})
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(changePassword.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to hash password"})
	}

	_, err = db.DB.Exec("UPDATE users SET password = ?, otp = NULL, otp_expiration = NULL WHERE email = ?", hashedPassword, changePassword.Email)
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to update password"})
	}

	return c.JSON(200, map[string]string{"message": "Password updated successfully"})

}
