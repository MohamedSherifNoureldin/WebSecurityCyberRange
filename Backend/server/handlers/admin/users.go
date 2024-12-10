package admin

import (
	"cyberrange/db"
	"cyberrange/types"
	"cyberrange/utils"
	"fmt"
	"strings"

	"github.com/labstack/echo/v4"
)

func GetUsers(c echo.Context) error {
	token := c.Request().Header.Get("Authorization")

	role := utils.GetRole(token)

	if role != "admin" {
		return c.JSON(401, map[string]string{"error": "Unauthorized"})
	}

	users := []types.User{}

	rows, err := db.DB.Query("SELECT email, user_id, name,attack_defense_role FROM users WHERE role = 'user'")
	if err != nil {
		fmt.Println(err)
		return c.JSON(500, map[string]string{"error": "Failed to get users"})
	}

	defer rows.Close()

	for rows.Next() {
		user := types.User{}
		err := rows.Scan(&user.Email, &user.User_id, &user.Name, &user.Attack_defense_role)
		if err != nil {
			fmt.Println(err)
			return c.JSON(500, map[string]string{"error": "Failed to get users"})
		}
		users = append(users, user)
	}

	return c.JSON(200, users)
}

func MakeAdmin(c echo.Context) error {

	token := c.Request().Header.Get("Authorization")

	role := utils.GetRole(token)

	if role != "admin" {
		return c.JSON(401, map[string]string{"error": "Unauthorized"})
	}

	email := c.QueryParam("email")

	_, err := db.DB.Exec("UPDATE users SET role = 'admin' WHERE email = ?", email)
	if err != nil {
		fmt.Println(err)
		return c.JSON(500, map[string]string{"error": "Failed to make the user admin"})
	}

	return c.JSON(200, map[string]string{"message": "User is now an admin"})
}

func DeleteUser(c echo.Context) error {
	token := c.Request().Header.Get("Authorization")

	role := utils.GetRole(token)

	if role != "admin" {
		return c.JSON(401, map[string]string{"error": "Unauthorized"})
	}

	email := c.QueryParam("email")

	email_without_domain := strings.Split(email, "@")[0]

	err := utils.DeleteContainerAndVolume(email_without_domain)
	if err != nil {
		fmt.Println(err)
	}

	var user_id, name string
	err = db.DB.QueryRow("SELECT user_id,name FROM users WHERE email = ?", email).Scan(&user_id, &name)
	if err != nil {
		fmt.Println(err)
		return c.JSON(500, map[string]string{"error": "Failed to delete the user"})
	}

	_, err = db.DB.Exec("DELETE FROM users WHERE email = ?", email)
	if err != nil {
		fmt.Println(err)
		return c.JSON(500, map[string]string{"error": "Failed to delete the user"})
	}

	_, err = db.DB.Exec("DELETE FROM ctf_solves WHERE name = ?", name)
	if err != nil {
		fmt.Println(err)
		return c.JSON(500, map[string]string{"error": "Failed to delete the user"})
	}

	_, err = db.DB.Exec("DELETE FROM labs_solves WHERE user_id = ?", user_id)
	if err != nil {
		fmt.Println(err)
		return c.JSON(500, map[string]string{"error": "Failed to delete the user"})
	}

	return c.JSON(200, map[string]string{"message": "User is deleted"})
}

func GetFeedbacks(c echo.Context) error {
	token := c.Request().Header.Get("Authorization")

	role := utils.GetRole(token)

	if role != "admin" {
		return c.JSON(401, map[string]string{"error": "Unauthorized"})
	}

	feedbacks := []types.Feedback{}

	rows, err := db.DB.Query("SELECT id, name, feedback,type ,created_at FROM feedback")
	if err != nil {
		fmt.Println(err)
		return c.JSON(500, map[string]string{"error": "Failed to get feedbacks"})
	}
	defer rows.Close()

	for rows.Next() {
		feedback := types.Feedback{}
		err := rows.Scan(&feedback.ID, &feedback.Name, &feedback.Feedback, &feedback.Type, &feedback.Created_at)
		if err != nil {
			fmt.Println(err)
			return c.JSON(500, map[string]string{"error": "Failed to get feedbacks"})
		}
		feedbacks = append(feedbacks, feedback)
	}

	return c.JSON(200, map[string]interface{}{"feedbacks": feedbacks})
}
