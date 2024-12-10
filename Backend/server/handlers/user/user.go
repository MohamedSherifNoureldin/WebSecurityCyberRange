package user

import (
	"fmt"
	"html"
	"time"

	"cyberrange/db"
	"cyberrange/types"
	"cyberrange/utils"

	"github.com/labstack/echo/v4"
)

func SubmitFlag(c echo.Context) error {
	token := c.Request().Header.Get("Authorization")

	role := utils.GetRole(token)

	if role != "user" {
		return c.JSON(401, map[string]string{"error": "Unauthorized"})
	}

	flag := c.QueryParam("flag")
	challenge := c.QueryParam("challenge")

	rows, err := db.DB.Query("SELECT flag,points FROM ctf_challenges WHERE name = $1", challenge)
	if err != nil {
		fmt.Println(err)
		return c.JSON(500, map[string]string{"error": "Failed to get flag"})
	}

	defer rows.Close()

	var correctFlag string
	var points int
	for rows.Next() {
		err := rows.Scan(&correctFlag, &points)
		if err != nil {
			fmt.Println(err)
			return c.JSON(500, map[string]string{"error": "Failed to get flag"})
		}
	}

	time := time.Now().Format("2006-01-02 15:04:05")

	if flag == correctFlag {
		_, err := db.DB.Exec("INSERT INTO ctf_solves (name, challenge_name,points,solve_date) VALUES ($1, $2, $3, $4)", utils.GetName(token), challenge, points, time)
		if err != nil {
			fmt.Println(err)
			return c.JSON(500, map[string]string{"error": "Failed to submit flag"})
		}

		return c.JSON(200, map[string]string{"message": "You have completed the challenge🎉"})
	}

	return c.JSON(400, map[string]string{"error": "Incorrect flag"})

}
func SendFeedback(c echo.Context) error {

	token := c.Request().Header.Get("Authorization")
	f := new(types.Feedback)
	if err := c.Bind(f); err != nil {
		return c.JSON(400, map[string]string{"error": "Invalid request"})
	}

	if f.Feedback == "" || f.Type == "" {
		return c.JSON(400, map[string]string{"error": "Please fill in all the required fields"})
	}

	name := utils.GetName(token)

	currentTime := time.Now().Format("2006-01-02 15:04:05")

	f.Feedback = html.EscapeString(f.Feedback)

	_, err := db.DB.Exec("INSERT INTO feedback (name, feedback,type, created_at) VALUES ($1, $2, $3, $4)", name, f.Feedback, f.Type, currentTime)
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Internal server error"})
	}

	return c.JSON(200, map[string]string{"message": "Feedback submitted successfully"})
}
