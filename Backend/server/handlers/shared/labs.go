package shared

import (
	"database/sql"
	"fmt"

	"cyberrange/db"
	t "cyberrange/types"
	"cyberrange/utils"

	"github.com/docker/docker/client"
	"github.com/lib/pq"

	"github.com/labstack/echo/v4"
)

var CLI *client.Client

func init() {
	var err error
	CLI, err = client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		fmt.Println(err)
	}

}
func GetLabs(c echo.Context) error {
	labs := []t.Lab{}
	solved_labs := []string{}
	solutions := make(map[string][]map[string]string)
	category := c.QueryParam("category")

	token := c.Request().Header.Get("Authorization")

	role := utils.GetRole(token)

	rows, err := db.DB.Query("SELECT id, name, description, container_names, isctf, shown FROM labs WHERE category = $1", category)
	if err != nil {
		fmt.Println(err)
		return c.JSON(500, map[string]string{"error": "Failed to get labs"})
	}
	defer rows.Close()

	for rows.Next() {
		lab := t.Lab{}
		err := rows.Scan(&lab.ID, &lab.Name, &lab.Description, pq.Array(&lab.ContainerNames), &lab.IsCTF, &lab.Shown)
		if err != nil {
			fmt.Println(err)
			return c.JSON(500, map[string]string{"error": "Failed to get labs"})
		}

		lab.ShownBoolean = lab.Shown == "true"

		if lab.Shown == "false" && role == "admin" {
			lab.Shown = ""
			labs = append(labs, lab)

		} else if lab.Shown == "true" {
			lab.Shown = ""
			labs = append(labs, lab)
		}
	}

	rows, err = db.DB.Query("SELECT lab_name FROM labs_solves WHERE category = $1 AND user_id = $2", category, utils.GetUserID(c.Request().Header.Get("Authorization")))
	if err != nil {
		fmt.Println(err)
		return c.JSON(500, map[string]string{"error": "Failed to get solved labs"})
	}
	defer rows.Close()

	for rows.Next() {
		var labName string
		err := rows.Scan(&labName)
		if err != nil {
			fmt.Println(err)
			return c.JSON(500, map[string]string{"error": "Failed to get solved labs"})
		}
		solved_labs = append(solved_labs, labName)
	}

	for i := range labs {
		for _, solved := range solved_labs {
			if labs[i].Name == solved {
				labs[i].IsSolved = true
				break
			}
		}
	}

	if role == "admin" {
		rows, err = db.DB.Query("SELECT lab_name, user_id FROM labs_solves WHERE category = $1", category)
		if err != nil {
			fmt.Println(err)
			return c.JSON(500, map[string]string{"error": "Failed to get lab solutions"})
		}
		defer rows.Close()

		for rows.Next() {
			var labName, userID string
			err := rows.Scan(&labName, &userID)
			if err != nil {
				fmt.Println(err)
				return c.JSON(500, map[string]string{"error": "Failed to get lab solutions"})
			}

			var userName, userEmail string
			err = db.DB.QueryRow("SELECT name, email FROM users WHERE user_id = $1", userID).Scan(&userName, &userEmail)
			if err != nil {
				fmt.Println(err)
				return c.JSON(500, map[string]string{"error": "Failed to get user details"})
			}

			solution := map[string]string{
				"id":    userID,
				"name":  userName,
				"email": userEmail,
			}

			solutions[labName] = append(solutions[labName], solution)
		}
	}

	if role == "admin" {
		return c.JSON(200, map[string]interface{}{
			"labs":   labs,
			"solves": solutions,
		})
	} else {
		return c.JSON(200, map[string]interface{}{
			"labs": labs,
		})
	}

}

func getLab(name string) (string, string, string, error) {
	composeFile := ""
	category := ""
	shown := ""
	err := db.DB.QueryRow("SELECT composefile, category,shown FROM labs WHERE name = $1", name).Scan(&composeFile, &category, &shown)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to get lab compose file: %w", err)
	}
	return composeFile, category, shown, nil
}

func GetCategories(c echo.Context) error {
	var categories []t.Category

	token := c.Request().Header.Get("Authorization")

	role := utils.GetRole(token)

	var query string
	if role == "admin" {
		query = `
			SELECT lc.name, COUNT(l.id) as number_of_labs
			FROM lab_categories lc
			LEFT JOIN labs l ON lc.name = l.category
			GROUP BY lc.name`
	} else {
		query = `
			SELECT lc.name, COUNT(l.id) as number_of_labs
			FROM lab_categories lc
			LEFT JOIN labs l ON lc.name = l.category AND l.shown = 'true'
			GROUP BY lc.name`
	}

	rows, err := db.DB.Query(query)
	if err != nil {
		fmt.Println(err)
		return c.JSON(500, map[string]string{"error": "Failed to get categories"})
	}
	defer rows.Close()

	for rows.Next() {
		var category t.Category
		var numberOfLabs sql.NullInt64

		err := rows.Scan(&category.Name, &numberOfLabs)
		if err != nil {
			fmt.Println(err)
			return c.JSON(500, map[string]string{"error": "Failed to get categories"})
		}

		if numberOfLabs.Valid {
			category.NumberOfLabs = numberOfLabs.Int64
		}

		categories = append(categories, category)
	}

	return c.JSON(200, categories)
}
