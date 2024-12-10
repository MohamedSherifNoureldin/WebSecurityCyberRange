package admin

import (
	"cyberrange/db"
	"cyberrange/types"
	"cyberrange/utils"
	"log"
	"path/filepath"
	"regexp"

	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/microcosm-cc/bluemonday"
	"github.com/robfig/cron/v3"

	"strconv"
)

var job *cron.Cron

var categories = [9]string{"Web Exploitation", "Forensics", "Cryptography", "Reverse Engineering", "Miscellaneous", "Network Security", "Binary Exploitation", "Steganography", "Warmup"}

func AddChallenge(c echo.Context) error {
	token := c.Request().Header.Get("Authorization")

	role := utils.GetRole(token)

	if role != "admin" {
		return c.JSON(401, map[string]string{"error": "Unauthorized"})
	}

	name := c.FormValue("name")
	description := c.FormValue("description")
	difficulty := c.FormValue("difficulty")
	flag := c.FormValue("flag")
	pointsStr := c.FormValue("points")
	hint := c.FormValue("hint")
	category := c.FormValue("category")
	var attachments []string

	if name == "" || description == "" || difficulty == "" || flag == "" || pointsStr == "" {
		return c.JSON(400, map[string]string{"error": "Please provide all the required fields"})
	}

	// Validate difficulty
	if difficulty != "Easy" && difficulty != "Medium" && difficulty != "Hard" && difficulty != "Insane" {
		return c.JSON(400, map[string]string{"error": "Invalid difficulty value"})
	}

	// Validate category
	if !isValidCategory(category, categories) {
		return c.JSON(400, map[string]string{"error": "Invalid category value"})
	}

	// Validate and parse points
	points, err := strconv.Atoi(pointsStr)
	if err != nil || points < 0 {
		return c.JSON(400, map[string]string{"error": "Points must be a positive integer"})
	}

	p := bluemonday.UGCPolicy()
	sanitizedDescription := p.Sanitize(description)

	// Handle attachments
	for key := range c.Request().MultipartForm.File {
		if strings.Contains(key, "file") {
			file, err := c.FormFile(key)
			if err != nil {
				return c.JSON(500, map[string]string{"error": "Failed to get file"})
			}

			src, err := file.Open()
			if err != nil {
				return c.JSON(500, map[string]string{"error": "Failed to open file"})
			}
			defer src.Close()

			safeFileName := filepath.Base(file.Filename)

			dstPath := filepath.Join("CyberRange/CTF", name, safeFileName)

			dst, err := os.Create(dstPath)
			if err != nil {
				return c.JSON(500, map[string]string{"error": "Failed to create file"})
			}
			defer dst.Close()

			_, err = io.Copy(dst, src)
			if err != nil {
				return c.JSON(500, map[string]string{"error": "Failed to save file"})
			}

			attachments = append(attachments, file.Filename)
		}
	}

	attachmentsStr := strings.Join(attachments, ",")

	// Add challenge to the database
	err = db.AddChallenge(name, sanitizedDescription, difficulty, flag, pointsStr, hint, category, attachmentsStr)
	if err != nil {
		fmt.Println(err)
		return c.JSON(500, map[string]string{"error": "Failed to add lab"})
	}

	return c.JSON(200, map[string]string{"message": "Challenge added successfully"})
}

func DeleteChallenge(c echo.Context) error {
	token := c.Request().Header.Get("Authorization")

	role := utils.GetRole(token)

	if role != "admin" {
		return c.JSON(401, map[string]string{"error": "Unauthorized"})
	}

	name := c.QueryParam("name")

	if name == "" {
		return c.JSON(400, map[string]string{"error": "Please provide the challenge Name"})
	}

	if !isValidChallengeName(name) {
		return c.JSON(400, map[string]string{"error": "Invalid challenge name"})
	}

	err := db.DeleteChallenge(name)
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to delete challenge"})
	}

	return c.JSON(200, map[string]string{"message": "Challenge deleted successfully"})
}

func isValidChallengeName(name string) bool {
	validName := regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	return validName.MatchString(name)
}

func GetSettings(c echo.Context) error {

	token := c.Request().Header.Get("Authorization")

	role := utils.GetRole(token)

	if role != "admin" {

		return c.JSON(401, map[string]string{"error": "Unauthorized"})
	}

	ctfType := c.QueryParam("type")

	settings, err := db.GetSettings(ctfType)
	if err != nil {
		fmt.Println(err)
		return c.JSON(500, map[string]string{"error": "Failed to get settings"})
	}

	return c.JSON(200, settings)
}

func SaveSettings(c echo.Context) error {
	token := c.Request().Header.Get("Authorization")

	role := utils.GetRole(token)

	if role != "admin" {
		return c.JSON(401, map[string]string{"error": "Unauthorized"})
	}

	ctfType := c.QueryParam("type")

	status := c.QueryParam("status")
	set_for_release := c.QueryParam("set_for_release")
	flag := c.QueryParam("flag")
	release_date := c.QueryParam("release_date")

	if set_for_release == "true" {

		if job != nil {
			job.Stop()
		}

		job = cron.New(cron.WithSeconds())

		_, err := job.AddFunc("@every 1m", func() {
			fmt.Println("Checking for release date")
			currentDate := time.Now().Format("2006-01-02T15:04")

			fmt.Println("Current date: ", currentDate)
			if release_date == currentDate {
				status = "true"
				set_for_release = "false"

				err := db.SaveSettings(status, set_for_release, flag, release_date, ctfType)
				if err != nil {
					fmt.Println(err)
					return
				}

				fmt.Println("Settings updated successfully")
			}
		})

		if err != nil {
			log.Printf("Error creating cron job: %v", err)
		}

		job.Start()
	} else {
		if job != nil {
			job.Stop()
		}

	}

	err := db.SaveSettings(status, set_for_release, flag, release_date, ctfType)
	if err != nil {
		fmt.Println(err)
		return c.JSON(500, map[string]string{"error": "Failed to save settings"})
	}

	return c.JSON(200, map[string]string{"message": "Settings saved successfully"})
}

func GetChallenges(c echo.Context) error {

	token := c.Request().Header.Get("Authorization")

	role := utils.GetRole(token)

	if role != "admin" {
		return c.JSON(401, map[string]string{"error": "Unauthorized"})
	}

	challenges := []types.Challenge{}

	rows, err := db.DB.Query("SELECT id, name, description, points, category, difficulty, hint, attachments FROM ctf_challenges")
	if err != nil {
		fmt.Println(err)
		return c.JSON(500, map[string]string{"error": "Failed to get labs"})
	}

	defer rows.Close()

	for rows.Next() {
		challenge := types.Challenge{}
		err := rows.Scan(&challenge.ID, &challenge.Name, &challenge.Description, &challenge.Points, &challenge.Category, &challenge.Difficulty, &challenge.Hint, &challenge.Attachments)
		if err != nil {
			fmt.Println(err)
			return c.JSON(500, map[string]string{"error": "Failed to get labs"})
		}
		challenges = append(challenges, challenge)
	}

	defer rows.Close()

	rows, err = db.DB.Query("SELECT flag FROM ctf where id = 1")
	if err != nil {
		fmt.Println(err)
		return c.JSON(500, map[string]string{"error": "Failed to get labs"})
	}

	defer rows.Close()

	var defaultFlag string
	for rows.Next() {
		err := rows.Scan(&defaultFlag)
		if err != nil {
			fmt.Println(err)
			return c.JSON(500, map[string]string{"error": "Failed to get labs"})
		}
	}

	defer rows.Close()

	return c.JSON(200, map[string]interface{}{"challenges": challenges, "defaultFlag": defaultFlag})
}

func isValidCategory(category string, categories [9]string) bool {
	for _, cat := range categories {
		if category == cat {
			return true
		}
	}
	return false
}
