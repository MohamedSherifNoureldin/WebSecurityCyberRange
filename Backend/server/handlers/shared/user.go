package shared

import (
	"fmt"
	"strings"

	"cyberrange/db"
	"cyberrange/types"
	"cyberrange/utils"

	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
)

func DeleteAccount(c echo.Context) error {
	token := c.Request().Header.Get("Authorization")
	user_id := utils.GetUserID(token)

	var email, name string
	err := db.DB.QueryRow("SELECT email,name FROM users WHERE user_id = $1", user_id).Scan(&email, &name)
	if err != nil {
		fmt.Println(err)
		return c.JSON(500, map[string]string{"error": "Failed to delete your account"})
	}

	_, err = db.DB.Exec("DELETE FROM users WHERE user_id = $1", user_id)
	if err != nil {
		fmt.Println(err)
		return c.JSON(500, map[string]string{"error": "Failed to delete your account"})
	}

	_, err = db.DB.Exec("DELETE FROM labs_solves WHERE user_id = $1", user_id)
	if err != nil {
		fmt.Println(err)
		return c.JSON(500, map[string]string{"error": "Failed to your account"})
	}

	_, err = db.DB.Exec("DELETE FROM ctf_solves WHERE name = $1", name)
	if err != nil {
		fmt.Println(err)
		return c.JSON(500, map[string]string{"error": "Failed to your account"})
	}

	email_without_domain := strings.Split(email, "@")[0]

	err = utils.DeleteContainerAndVolume(email_without_domain)
	if err != nil {
		fmt.Println(err)
		return c.JSON(500, map[string]string{"error": "Failed to delete your account"})
	}

	return c.JSON(200, map[string]string{"message": "Account is deleted successfully!"})
}

func UpdateAccount(c echo.Context) error {
	token := c.Request().Header.Get("Authorization")
	user_id := utils.GetUserID(token)

	var req types.RequestUpdateAccount
	if err := c.Bind(&req); err != nil {
		return c.JSON(400, map[string]string{"error": "Invalid request body"})
	}

	var hashedPassword []byte
	var err error

	if req.NewPassword == "" || req.OldPassword == "" {
		return c.JSON(400, map[string]string{"error": "New or Old Password cannot be empty"})
	}

	if req.NewPassword == req.OldPassword {
		return c.JSON(400, map[string]string{"error": "New password must be different from the old password"})
	}

	var password string
	err = db.DB.QueryRow("SELECT password FROM users WHERE user_id = $1", user_id).Scan(&password)
	if err != nil {
		fmt.Println(err)
		return c.JSON(500, map[string]string{"error": "Could not get your account"})
	}

	err = bcrypt.CompareHashAndPassword([]byte(password), []byte(req.OldPassword))
	if err != nil {
		fmt.Println("here")
		return c.JSON(400, map[string]string{"error": "Old password is incorrect"})
	}

	hashedPassword, err = bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to hash password"})
	}

	if req.Name != "" && len(req.Name) < 3 {
		return c.JSON(400, map[string]string{"error": "Name must be at least 3 characters"})
	}

	if req.Name != "" && len(req.Name) > 64 {
		return c.JSON(400, map[string]string{"error": "Name must be at most 64 characters"})
	}

	if req.Name != "" && req.NewPassword != "" && req.OldPassword != "" {
		_, err = db.DB.Exec("UPDATE users SET name = $1, password = $2 WHERE user_id = $3", req.Name, string(hashedPassword), user_id)
	} else if req.Name != "" {
		_, err = db.DB.Exec("UPDATE users SET name = $1 WHERE user_id = $2", req.Name, user_id)
	} else if req.NewPassword != "" && req.OldPassword != "" {
		_, err = db.DB.Exec("UPDATE users SET password = $1 WHERE user_id = $2", string(hashedPassword), user_id)
	}

	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to update your account"})
	}

	return c.JSON(200, map[string]string{"message": "Account is updated successfully!"})
}
