package shared

import (
	"bytes"
	"database/sql"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"cyberrange/db"
	"cyberrange/types"
	"cyberrange/utils"

	"github.com/labstack/echo/v4"

	"regexp"
)

func DownloadAttachment(c echo.Context) error {
	name := c.QueryParam("filename")
	challenge := c.QueryParam("challenge")

	// Sanitize input
	validName := regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
	if !validName.MatchString(name) || !validName.MatchString(challenge) {
		return c.JSON(400, map[string]string{"error": "Invalid input"})
	}

	// Construct the file path and enforce root directory constraint
	rootDir, err := filepath.Abs(filepath.Join("CyberRange", "CTF"))
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to resolve root directory"})
	}

	filePath, err := filepath.Abs(filepath.Join(rootDir, challenge, name))
	if err != nil || !strings.HasPrefix(filePath, rootDir) {
		return c.JSON(403, map[string]string{"error": "Access denied"})
	}

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return c.JSON(404, map[string]string{"error": "File not found"})
	}

	return c.File(filePath)
}

func DownloadAll(c echo.Context) error {
	challenge := c.QueryParam("challenge")

	// Sanitize input
	validChallenge := regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
	if !validChallenge.MatchString(challenge) {
		return c.JSON(400, map[string]string{"error": "Invalid input"})
	}

	// Construct the directory path and enforce root directory constraint
	rootDir, err := filepath.Abs(filepath.Join("../CyberRange", "CTF"))
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to resolve root directory"})
	}

	challengeDir, err := filepath.Abs(filepath.Join(rootDir, challenge))
	fmt.Printf("Dir is %s\n", challengeDir)
	if err != nil || !strings.HasPrefix(challengeDir, rootDir) {
		return c.JSON(403, map[string]string{"error": "Access denied"})
	}

	if _, err := os.Stat(challengeDir); os.IsNotExist(err) {
		return c.JSON(404, map[string]string{"error": "Folder not found"})
	}

	// Calculate folder size
	var totalSize int64
	err = filepath.Walk(challengeDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			totalSize += info.Size()
		}
		return nil
	})
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to calculate folder size"})
	}

	// Enforce size limit
	if totalSize > 100*1024 {
		return c.JSON(413, map[string]string{"error": "Folder too large to zip"})
	}

	// Create zip file
	zipPath := challengeDir + ".zip"
	err = utils.Zip(challengeDir, zipPath)
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to zip folder"})
	}

	defer os.Remove(zipPath)

	return c.File(zipPath)
}

func IsAdmin(c echo.Context) error {
	token := c.Request().Header.Get("Authorization")

	role := utils.GetRole(token)

	if role != "admin" {
		return c.JSON(401, map[string]string{"error": "Unauthorized"})
	}

	return c.JSON(200, map[string]string{"message": "You are an admin"})
}

func GetJeopardyCTF(c echo.Context) error {
	challenges := []types.Challenge{}
	token := c.Request().Header.Get("Authorization")
	name := utils.GetName(token)

	rows, err := db.DB.Query(`
    SELECT c.id, c.name, c.description, c.points, c.category, c.difficulty, c.hint, c.attachments, s.name
    FROM ctf_challenges c
    LEFT JOIN ctf_solves s ON c.name = s.challenge_name AND s.name = $1`, name)
	if err != nil {
		fmt.Println(err)
		return c.JSON(500, map[string]string{"error": "Failed to get labs"})
	}

	defer rows.Close()

	for rows.Next() {
		challenge := types.Challenge{}
		var solved sql.NullString
		err := rows.Scan(&challenge.ID, &challenge.Name, &challenge.Description, &challenge.Points, &challenge.Category, &challenge.Difficulty, &challenge.Hint, &challenge.Attachments, &solved)
		if err != nil {
			fmt.Println(err)
			return c.JSON(500, map[string]string{"error": "Failed to get labs"})
		}
		challenge.IsSolved = solved.Valid

		row := db.DB.QueryRow("SELECT COUNT(*) FROM ctf_solves WHERE challenge_name = $1", challenge.Name)
		err = row.Scan(&challenge.Solves)
		if err != nil {
			fmt.Println(err)
			return c.JSON(500, map[string]string{"error": "Failed to get solves"})
		}

		challenges = append(challenges, challenge)
	}

	rows, err = db.DB.Query("SELECT flag, status,set_for_release,release_date FROM ctf where id = 1")
	if err != nil {
		fmt.Println(err)
		return c.JSON(500, map[string]string{"error": "Failed to get labs"})
	}

	defer rows.Close()

	var defaultFlag, status, setForRelease, releaseDate string
	for rows.Next() {
		err := rows.Scan(&defaultFlag, &status, &setForRelease, &releaseDate)
		if err != nil {
			fmt.Println(err)
			return c.JSON(500, map[string]string{"error": "Failed to get labs"})
		}
	}

	var score int64
	if status == "true" {
		rows, err := db.DB.Query("SELECT SUM(points) FROM ctf_solves WHERE name = $1", name)
		if err != nil {
			log.Printf("Failed to execute query: %v", err)

		}
		defer rows.Close()

		if rows.Next() {
			err := rows.Scan(&score)
			if err != nil {
				log.Printf("Failed to scan row: %v", err)

			}
		}
	}

	if status == "true" {
		return c.JSON(200, map[string]interface{}{"challenges": challenges, "defaultFlag": defaultFlag, "score": score})
	} else if status == "false" && setForRelease == "true" {
		return c.JSON(200, map[string]interface{}{"release_date": releaseDate})
	} else if status == "inactive" && setForRelease == "false" {
		return c.JSON(200, map[string]string{"message": "CTF 1s c0m1ng s00n!"})
	}

	return c.JSON(200, map[string]string{"message": "CTF 1s c0m1ng s00n!"})

}

func GetScoreboard(c echo.Context) error {
	token := c.Request().Header.Get("Authorization")

	username := utils.GetName(token)
	role := utils.GetRole(token)

	rows, err := db.DB.Query("SELECT status,set_for_release,release_date FROM ctf where id = 1")
	if err != nil {
		fmt.Println(err)
		return c.JSON(500, map[string]string{"error": "Failed to get labs"})
	}

	defer rows.Close()

	var status, setForRelease, releaseDate string
	for rows.Next() {
		err := rows.Scan(&status, &setForRelease, &releaseDate)
		if err != nil {
			fmt.Println(err)
			return c.JSON(500, map[string]string{"error": "Failed to get labs"})
		}
	}

	if status == "false" && setForRelease == "true" {
		return c.JSON(200, map[string]interface{}{"release_date": releaseDate})
	} else if status == "false" && setForRelease == "false" {
		return c.JSON(200, map[string]string{"message": "CTF 1s c0m1ng s00n!"})
	}

	scoreboard := []map[string]interface{}{}

	rows, err = db.DB.Query("SELECT name FROM users WHERE role='user'")
	if err != nil {
		fmt.Println(err)
		return c.JSON(500, map[string]string{"error": "Failed to get users"})
	}

	defer rows.Close()

	for rows.Next() {
		user := map[string]interface{}{}
		var name string
		err := rows.Scan(&name)
		if err != nil {
			fmt.Println(err)
			return c.JSON(500, map[string]string{"error": "Failed to scan row"})
		}

		rows, err := db.DB.Query("SELECT SUM(points) FROM ctf_solves WHERE name = $1", name)
		if err != nil {
			log.Printf("Failed to execute query: %v", err)
			return c.JSON(500, map[string]string{"error": "Failed to get the sum of points"})
		}
		defer rows.Close()

		var score int64
		for rows.Next() {
			err := rows.Scan(&score)
			if err != nil && !strings.Contains(err.Error(), "converting NULL to int64 is unsupported") {
				log.Printf("Failed to scan row: %v", err)
				return c.JSON(500, map[string]string{"error": "Failed to scan the score"})
			}
		}

		user["name"] = name
		user["score"] = score
		scoreboard = append(scoreboard, user)

		fmt.Println(scoreboard)
	}

	sort.Slice(scoreboard, func(i, j int) bool {
		if scoreboard[i]["score"].(int64) == scoreboard[j]["score"].(int64) {
			return strings.ToLower(scoreboard[i]["name"].(string)) < strings.ToLower(scoreboard[j]["name"].(string))
		}
		return scoreboard[i]["score"].(int64) > scoreboard[j]["score"].(int64)
	})

	prevScore := int64(-1)
	rank := 0
	userindex := 0
	for k, user := range scoreboard {
		if user["name"] == username {
			userindex = k
		}

		score := user["score"].(int64)
		if score != prevScore {
			rank++
		}
		user["rank"] = rank

		if score == 0 {
			user["name"] = "🤡 " + user["name"].(string)
		} else if rank == 1 {
			user["name"] = "🥇 " + user["name"].(string)
		} else if rank == 2 {
			user["name"] = "🥈 " + user["name"].(string)
		} else if rank == 3 {
			user["name"] = "🥉 " + user["name"].(string)
		} else if rank == 4 {
			user["name"] = "🌟 " + user["name"].(string)
		} else if rank == 5 {
			user["name"] = "🔥 " + user["name"].(string)
		} else if score > 0 {
			user["name"] = "🐢 " + user["name"].(string)
		}

		prevScore = score
	}

	if role == "user" {

		return c.JSON(200, map[string]interface{}{"scoreboard": scoreboard, "userindex": userindex})
	} else {

		return c.JSON(200, map[string]interface{}{"scoreboard": scoreboard})

	}

}

type User struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

func GetAttackDefenseCTF(c echo.Context) error {
	token := c.Request().Header.Get("Authorization")
	uid := utils.GetUserID(token)
	rows, err := db.DB.Query("SELECT status,set_for_release,release_date,docker_image FROM ctf where id = 2")
	if err != nil {
		fmt.Println(err)
		return c.JSON(500, map[string]string{"error": "Failed to get labs"})
	}

	defer rows.Close()

	var status, setForRelease, releaseDate, dockerImage string
	for rows.Next() {
		err := rows.Scan(&status, &setForRelease, &releaseDate, &dockerImage)
		if err != nil {
			fmt.Println(err)
			return c.JSON(500, map[string]string{"error": "Failed to get labs"})
		}
	}

	if status == "false" && setForRelease == "true" {
		return c.JSON(200, map[string]interface{}{"release_date": releaseDate})
	} else if status == "false" && setForRelease == "false" {
		return c.JSON(200, map[string]interface{}{"message": "CTF 1s c0m1ng s00n!", "live": false})
	}

	rows, err = db.DB.Query("SELECT user_id,email, name, attack_defense_role FROM users WHERE role='user'")
	if err != nil {
		fmt.Println(err)
		return c.JSON(500, map[string]string{"error": "Failed to get users"})
	}
	defer rows.Close()

	var team []User
	var userRole string
	var foundUser bool

	for rows.Next() {
		var user_id, email, name, attack_defense_role string
		err := rows.Scan(&user_id, &email, &name, &attack_defense_role)
		if err != nil {
			fmt.Println(err)
			return c.JSON(500, map[string]string{"error": "Failed to scan row"})
		}

		if user_id == uid {
			userRole = attack_defense_role
			foundUser = true
		}

		if attack_defense_role == "Defender" && userRole == "Defender" {
			team = append(team, User{Email: email, Name: name})
		} else if attack_defense_role == "Attacker" && userRole == "Attacker" {
			team = append(team, User{Email: email, Name: name})
		}
	}

	if !foundUser {
		return c.JSON(404, map[string]string{"error": "User not found"})
	}

	if userRole == "Out" {
		return c.JSON(200, map[string]interface{}{"ready": "false", "role": "Out", "live": true})
	}

	response := map[string]interface{}{
		"role": userRole,
		"team": team,
		"live": true,
	}

	if dockerImage != "none" {
		response["ready"] = true
	} else {
		response["ready"] = false
	}

	return c.JSON(200, response)
}

func SubmitCTFImage(c echo.Context) error {
	token := c.Request().Header.Get("Authorization")

	uid := utils.GetUserID(token)
	dockerImage := c.QueryParam("dockerimage")

	rows, err := db.DB.Query("SELECT status FROM ctf where id = 2")
	if err != nil {
		fmt.Println(err)
		return c.JSON(500, map[string]string{"error": "Failed to get ctf"})
	}

	defer rows.Close()

	var status string
	for rows.Next() {

		err := rows.Scan(&status)
		if err != nil {
			fmt.Println(err)
			return c.JSON(500, map[string]string{"error": "Failed to get ctf"})
		}
	}

	if status == "false" {
		return c.JSON(300, map[string]string{"message": "CTF is not active"})
	}

	rows, err = db.DB.Query("SELECT attack_defense_role FROM users WHERE user_id = ?", uid)
	if err != nil {
		fmt.Println(err)
		return c.JSON(500, map[string]string{"error": "Failed to get user"})
	}

	defer rows.Close()

	var attackDefenseRole string
	for rows.Next() {
		err := rows.Scan(&attackDefenseRole)
		if err != nil {
			fmt.Println(err)
			return c.JSON(500, map[string]string{"error": "Failed to get user"})
		}
	}

	if attackDefenseRole != "Defender" {
		return c.JSON(300, map[string]string{"message": "You are not a Defender"})
	}

	if dockerImage == "" {
		dockerImage = "none"
		_, err = db.DB.Exec("UPDATE ctf SET docker_image = ? WHERE id = 2", dockerImage)
		if err != nil {
			fmt.Println(err)
			return c.JSON(500, map[string]string{"error": "Failed to update image"})
		}

		return c.JSON(200, map[string]bool{"ready": false})

	}

	fmt.Printf("Pulling image: %s\n", dockerImage)

	cmd := exec.Command("docker", "pull", dockerImage)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		fmt.Printf("Error pulling image %s: %s\n", dockerImage, stderr.String())
		return fmt.Errorf("failed to pull image %s: %v", dockerImage, err)
	}

	fmt.Printf("Successfully pulled image: %s\n", dockerImage)
	fmt.Printf("Output: %s\n", out.String())

	cmd = exec.Command("docker", "rm", "-vf", "attackdefensectf")
	err = cmd.Run()
	if err != nil {
		fmt.Printf("Error removing container attackdefensectf: %s\n", stderr.String())
		return fmt.Errorf("failed to remove container attackdefensectf: %v", err)
	}

	cmd = exec.Command("docker", "run", "-d", "-p", "3000", "--name", "attackdefensectf", dockerImage)
	err = cmd.Run()
	if err != nil {
		fmt.Printf("Error running image %s: %s\n", dockerImage, stderr.String())
		return fmt.Errorf("failed to run image %s: %v", dockerImage, err)
	}

	_, err = db.DB.Exec("UPDATE ctf SET docker_image = ? WHERE id = 2", dockerImage)
	if err != nil {
		fmt.Println(err)
		return c.JSON(500, map[string]string{"error": "Failed to update docker image"})
	}

	return c.JSON(200, map[string]interface{}{"message": "Docker image submitted successfully", "ready": true})

}

func StartTheAttack(c echo.Context) error {
	port := utils.GetCTFContainerPort()

	return c.JSON(200, map[string]interface{}{"port": port})
}
