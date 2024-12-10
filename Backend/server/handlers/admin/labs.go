package admin

import (
	"cyberrange/db"
	"cyberrange/utils"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/labstack/echo/v4"
)

func AddLab(c echo.Context) error {
	token := c.Request().Header.Get("Authorization")

	role := utils.GetRole(token)

	if role != "admin" {
		return c.JSON(401, map[string]string{"error": "Unauthorized"})
	}

	name := c.FormValue("name")
	description := c.FormValue("description")
	category := c.FormValue("category")
	isctf := c.FormValue("isctf")

	if name == "" || description == "" || category == "" {
		return c.JSON(400, map[string]string{"error": "Please provide all the required fields"})
	}

	composeFile, err := c.FormFile("composefile")
	if err != nil {
		return c.JSON(400, map[string]string{"error": "Please upload a Compose file"})
	}

	ext := filepath.Ext(composeFile.Filename)
	if ext != ".yml" && ext != ".yaml" {
		return c.JSON(400, map[string]string{"error": "Please upload a Compose file"})
	}

	src, err := composeFile.Open()
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to open file"})
	}

	defer src.Close()

	fileBytes, err := io.ReadAll(src)
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to read file"})
	}

	services, err := utils.GetServices(fileBytes)
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to get services"})
	}
	go func() {
		if err := utils.ExtractAndDownloadImages(fileBytes); err != nil {
			fmt.Printf("Error extracting and downloading images: %v\n", err)
		}
	}()

	name = strings.TrimSpace(name)
	err = db.AddLab(name, description, string(fileBytes), services, category, isctf)
	if err != nil {
		fmt.Println(err)
		return c.JSON(500, map[string]string{"error": "Failed to add lab"})
	}

	return c.JSON(200, map[string]string{"message": "Lab added successfully"})

}

func DeleteLab(c echo.Context) error {
	token := c.Request().Header.Get("Authorization")

	role := utils.GetRole(token)

	if role != "admin" {

		return c.JSON(401, map[string]string{"error": "Unauthorized"})
	}

	name := c.QueryParam("name")

	if name == "" {
		return c.JSON(400, map[string]string{"error": "Please provide the lab Name"})
	}

	err := db.DeleteLab(name)
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to delete lab"})
	}

	return c.JSON(200, map[string]string{"message": "Lab deleted successfully"})
}

func AddCategory(c echo.Context) error {
	token := c.Request().Header.Get("Authorization")

	role := utils.GetRole(token)

	if role != "admin" {

		return c.JSON(401, map[string]string{"error": "Unauthorized"})
	}

	name := c.FormValue("name")

	err := db.AddCategory(name)
	if err != nil {
		fmt.Println(err)
		return c.JSON(500, map[string]string{"error": "Failed to add category"})
	}

	return c.JSON(200, map[string]string{"message": "Category added successfully"})
}

func DeleteCategory(c echo.Context) error {
	token := c.Request().Header.Get("Authorization")

	role := utils.GetRole(token)

	if role != "admin" {

		return c.JSON(401, map[string]string{"error": "Unauthorized"})
	}

	name := c.QueryParam("name")

	if name == "" {
		return c.JSON(400, map[string]string{"error": "Please provide the category Name"})
	}

	err := db.DeleteCategory(name)
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to delete category"})
	}

	return c.JSON(200, map[string]string{"message": "Category deleted successfully"})
}

func UpdateLabStatus(c echo.Context) error {

	token := c.Request().Header.Get("Authorization")

	role := utils.GetRole(token)

	if role != "admin" {
		return c.JSON(401, map[string]string{"error": "Unauthorized"})
	}

	name := c.QueryParam("name")
	shown := c.QueryParam("shown")

	err := db.UpdateLabStatus(name, shown)
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to update lab status"})
	}

	return c.JSON(200, map[string]string{"message": "Lab status updated successfully"})
}
