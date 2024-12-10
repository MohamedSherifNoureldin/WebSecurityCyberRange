package user

import (
	"fmt"
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
	username := utils.GetName(token)

	// Check if the user has already submitted the flag for the challenge
	var exists bool
	err := db.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM ctf_solves WHERE name = $1 AND challenge_name = $2)", username, challenge).Scan(&exists)
	if err != nil {
		fmt.Println(err)
		return c.JSON(500, map[string]string{"error": "Failed to check flag submission"})
	}

	if exists {
		return c.JSON(400, map[string]string{"error": "You have already submitted the correct flag for this challenge"})
	}

	// Retrieve the correct flag and points for the challenge
	rows, err := db.DB.Query("SELECT flag, points FROM ctf_challenges WHERE name = $1", challenge)
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

	// Validate the submitted flag
	if flag == correctFlag {
		time := time.Now().Format("2006-01-02 15:04:05")

		// Insert the solve record
		_, err := db.DB.Exec("INSERT INTO ctf_solves (name, challenge_name, points, solve_date) VALUES ($1, $2, $3, $4)", username, challenge, points, time)
		if err != nil {
			fmt.Println(err)
			return c.JSON(500, map[string]string{"error": "Failed to submit flag"})
		}

		return c.JSON(200, map[string]string{"message": "You have completed the challenge 🎉"})
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

	_, err := db.DB.Exec("INSERT INTO feedback (name, feedback,type, created_at) VALUES ($1, $2, $3, $4)", name, f.Feedback, f.Type, currentTime)
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Internal server error"})
	}

	return c.JSON(200, map[string]string{"message": "Feedback submitted successfully"})
}
