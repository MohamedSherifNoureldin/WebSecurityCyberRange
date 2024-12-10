package user

import (
	"github.com/labstack/echo/v4"

	"cyberrange/db"
)

type Msg struct {
	Name    string `json:"name"`
	Email   string `json:"email"`
	Message string `json:"message"`
}

func Contactus(c echo.Context) error {

	m := new(Msg)
	if err := c.Bind(m); err != nil {
		return c.JSON(400, map[string]string{"error": "Invalid request"})
	}

	if m.Email == "" || m.Name == "" || m.Message == "" {
		return c.JSON(400, map[string]string{"error": "Please fill in all the required fields"})
	}

	if len(m.Message) > 1000 {
		return c.JSON(400, map[string]string{"error": "Message should not be more than 1000 characters"})
	}

	_, err := db.DB.Exec("INSERT INTO contactus (name, email, message) VALUES ($1, $2, $3)", m.Name, m.Email, m.Message)
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to submit message"})
	}

	return c.JSON(200, map[string]string{"message": "Message submitted successfully"})
}
