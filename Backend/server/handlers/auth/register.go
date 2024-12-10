package auth

import (
	"cyberrange/db"
	"cyberrange/types"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
)

func Register(c echo.Context) error {
	user := types.UserRegister{}

	if err := c.Bind(&user); err != nil {
		return c.JSON(400, map[string]string{"error": err.Error()})
	}

	if user.ID == "" || user.Email == "" || user.Password == "" || user.Name == "" {
		return c.JSON(400, map[string]string{"error": "Please provide all the required fields"})
	}

	var id string
	err := db.DB.QueryRow("SELECT user_id FROM users WHERE user_id = $1", user.ID).Scan(&id)
	if err == nil {
		return c.JSON(400, map[string]string{"error": "ID already exists"})
	}

	err = db.DB.QueryRow("SELECT email FROM users WHERE email = $1", user.Email).Scan(&id)
	if err == nil {
		return c.JSON(400, map[string]string{"error": "Email already exists"})
	}

	user.Email = strings.ToLower(user.Email)

	re := regexp.MustCompile(`^[a-z0-9._%+\-]+@aucegypt\.edu$`)
	if !re.MatchString(user.Email) {
		return c.JSON(400, map[string]string{"error": "Please enter a valid AUC email"})
	}

	if len(user.Password) < 8 || len(user.Password) > 64 {
		return c.JSON(400, map[string]string{"error": "Password must be at least 8 characters and at most 64 characters"})
	}

	if len(user.Name) < 3 || len(user.Name) > 64 {
		return c.JSON(400, map[string]string{"error": "Name must be at least 3 characters"})
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to hash password"})
	}

	_, err = db.DB.Exec("INSERT INTO users (user_id, email, name, role, password) VALUES ($1, $2, $3, $4, $5)", user.ID, user.Email, user.Name, "user", string(hashedPassword))
	if err != nil {
		fmt.Println(err)
		return c.JSON(500, map[string]string{"error": "Failed to insert user"})
	}

	return c.JSON(200, map[string]string{"message": "User registered successfully!"})

}

func RegisterAdmin(c echo.Context) error {
	var count int

	err := db.DB.QueryRow("SELECT COUNT(*) FROM users where role='admin'").Scan(&count)
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to get users"})
	}

	if count > 0 {
		return c.JSON(400, map[string]string{"error": "Admin already exists"})
	}

	user := types.UserRegister{}

	if err := c.Bind(&user); err != nil {
		return c.JSON(400, map[string]string{"error": err.Error()})
	}

	if user.ID == "" || user.Email == "" || user.Password == "" || user.Name == "" {
		return c.JSON(400, map[string]string{"error": "Please provide all the required fields"})
	}

	var id string
	err = db.DB.QueryRow("SELECT user_id FROM users WHERE user_id = $1", user.ID).Scan(&id)
	if err == nil {
		return c.JSON(400, map[string]string{"error": "ID already exists"})
	}

	err = db.DB.QueryRow("SELECT email FROM users WHERE email = $1", user.Email).Scan(&id)
	if err == nil {
		return c.JSON(400, map[string]string{"error": "Email already exists"})
	}

	re := regexp.MustCompile(`^[a-z0-9._%+\-]+@aucegypt\.edu$`)
	if !re.MatchString(user.Email) {
		return c.JSON(400, map[string]string{"error": "Please enter a valid AUC email"})
	}

	if len(user.Password) < 6 {
		return c.JSON(400, map[string]string{"error": "Password must be at least 6 characters"})
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to hash password"})
	}

	_, err = db.DB.Exec("INSERT INTO users (user_id, email, name, role, password) VALUES ($1, $2, $3, $4, $5)", user.ID, user.Email, user.Name, "admin", string(hashedPassword))
	if err != nil {
		fmt.Println(err)
		return c.JSON(500, map[string]string{"error": "Failed to insert user"})
	}

	email := strings.Split(user.Email, "@")[0]

	dirPath := fmt.Sprintf("CyberRange/Volumes/%s", email)

	err = os.RemoveAll(dirPath)
	if err != nil {
		log.Fatalf("Unable to remove volume folder\n%s", err.Error())
	}

	err = os.Mkdir(dirPath, 0755)
	if err != nil {
		log.Fatalf("Unable to create volume folder\n%s", err.Error())
	}

	cmdName := "cp"
	cmdArgs := []string{"CyberRange/select_machine.sh", "CyberRange/Volumes/" + email}
	cmd := exec.Command(cmdName, cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to execute command: %w", err)
	}

	return c.JSON(200, map[string]string{"message": "Admin registered successfully!"})
}
