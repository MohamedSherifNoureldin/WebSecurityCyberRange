package utils

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/golang-jwt/jwt"
	"gopkg.in/yaml.v2"
)

func ValidateToken(token string) bool {
	token = strings.TrimPrefix(token, "Bearer ")

	_, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err != nil {
		fmt.Println(err)
		return false
	}

	return true
}

func GetRole(token string) string {
	token = strings.TrimPrefix(token, "Bearer ")

	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err != nil {
		fmt.Println(err)
		return ""
	}

	role, ok := claims["role"].(string)
	if !ok {
		return ""
	}

	return role
}

func GetName(token string) string {
	token = strings.TrimPrefix(token, "Bearer ")

	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err != nil {
		fmt.Println(err)
		return ""
	}

	name, ok := claims["name"].(string)
	if !ok {
		return ""
	}

	return name
}

func GetUserID(token string) string {
	token = strings.TrimPrefix(token, "Bearer ")

	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err != nil {
		fmt.Println(err)
		return ""
	}

	userID, ok := claims["user_id"].(string)
	if !ok {
		return ""
	}

	return userID
}

func GetID(token string) string {
	token = strings.TrimPrefix(token, "Bearer ")

	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err != nil {
		return ""
	}

	id, ok := claims["id"].(string)
	if !ok {
		return ""
	}

	return id
}

func GetContainerID(token string) string {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return ""
	}

	conts, err := cli.ContainerList(context.Background(), container.ListOptions{})
	if err != nil {
		return ""
	}

	var containerID string

	id := GetID(token)

	for _, container := range conts {
		if strings.Contains(container.Names[0], id) {
			containerID = container.ID
			break
		}
	}

	if containerID == "" {
		return ""
	} else {
		return containerID
	}

}

func GetServices(fileBytes []byte) ([]string, error) {
	reader := bytes.NewReader(fileBytes)

	var composeFile struct {
		Services map[string]interface{} `yaml:"services"`
	}

	decoder := yaml.NewDecoder(reader)
	if err := decoder.Decode(&composeFile); err != nil {
		return nil, err
	}

	var services []string
	for serviceName := range composeFile.Services {

		if serviceName[0] == 'X' {
			continue
		}

		services = append(services, serviceName)

	}

	sort.Strings(services)
	return services, nil
}

func ExtractAndDownloadImages(fileBytes []byte) error {
	reader := bytes.NewReader(fileBytes)

	var composeFile struct {
		Services map[string]struct {
			Image string `yaml:"image"`
		} `yaml:"services"`
	}

	decoder := yaml.NewDecoder(reader)
	if err := decoder.Decode(&composeFile); err != nil {
		return fmt.Errorf("failed to decode YAML: %v", err)
	}

	var images []string
	for _, service := range composeFile.Services {
		if service.Image != "" {
			images = append(images, service.Image)
		}
	}

	sort.Strings(images)

	existingImages, err := getExistingImages()
	if err != nil {
		return fmt.Errorf("failed to get existing images: %v", err)
	}

	for _, image := range images {
		if _, exists := existingImages[image]; exists {
			continue
		}

		fmt.Printf("Pulling image: %s\n", image)

		cmd := exec.Command("docker", "pull", image)
		var out bytes.Buffer
		var stderr bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &stderr

		err := cmd.Run()
		if err != nil {
			fmt.Printf("Error pulling image %s: %s\n", image, stderr.String())
			return fmt.Errorf("failed to pull image %s: %v", image, err)
		}

		fmt.Printf("Successfully pulled image: %s\n", image)
		fmt.Printf("Output: %s\n", out.String())
	}

	return nil
}

func getExistingImages() (map[string]struct{}, error) {
	cmd := exec.Command("docker", "images", "--format", "{{.Repository}}:{{.Tag}}")
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("failed to list existing images: %s", stderr.String())
	}

	images := make(map[string]struct{})
	for _, line := range strings.Split(out.String(), "\n") {
		if line != "" {
			images[line] = struct{}{}
		}
	}

	return images, nil
}

func GetContainerIP(token string) string {

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return ""
	}

	conts, err := cli.ContainerList(context.Background(), container.ListOptions{})
	if err != nil {
		return ""
	}

	var containerID string

	id := GetID(token)

	for _, container := range conts {
		if strings.Contains(container.Names[0], id) {
			containerID = container.ID
			break
		}
	}

	if containerID == "" {
		return ""
	}

	container, err := cli.ContainerInspect(context.Background(), containerID)
	if err != nil {
		return ""
	}

	network := container.NetworkSettings.Networks[id]
	if network == nil {
		return ""
	}
	return network.IPAddress
}

func GetWebContainerPort(token string) string {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return ""
	}

	conts, err := cli.ContainerList(context.Background(), container.ListOptions{})
	if err != nil {
		return ""
	}

	var containerID string
	id := GetID(token)

	for _, container := range conts {
		if strings.Contains(container.Names[0], id) {
			containerID = container.ID
			break
		}
	}

	if containerID == "" {
		return ""
	}

	container, err := cli.ContainerInspect(context.Background(), containerID)
	if err != nil {
		return ""
	}

	portBindings := container.NetworkSettings.Ports["6080/tcp"]
	if len(portBindings) == 0 {
		return ""
	}

	fmt.Println(portBindings)

	fmt.Println("Port:", portBindings[0].HostPort)
	return portBindings[0].HostPort
}

func GetCTFContainerPort() string {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return ""
	}

	conts, err := cli.ContainerList(context.Background(), container.ListOptions{})
	if err != nil {
		return ""
	}

	var containerID string

	for _, container := range conts {
		if strings.Contains(container.Names[0], "attackdefensectf") {
			containerID = container.ID
			break
		}
	}

	if containerID == "" {
		return ""
	}

	container, err := cli.ContainerInspect(context.Background(), containerID)
	if err != nil {
		return ""
	}

	portBindings := container.NetworkSettings.Ports["3000/tcp"]
	if len(portBindings) == 0 {
		return ""
	}

	fmt.Println("Port:", portBindings[0].HostPort)
	return portBindings[0].HostPort
}

func GetCoderPort(token string) string {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return ""
	}

	conts, err := cli.ContainerList(context.Background(), container.ListOptions{})
	if err != nil {
		return ""
	}

	var containerID string
	id := GetID(token)

	for _, container := range conts {
		if strings.Contains(container.Names[0], id) {
			containerID = container.ID
			break
		}
	}

	if containerID == "" {
		return ""
	}

	container, err := cli.ContainerInspect(context.Background(), containerID)
	if err != nil {
		return ""
	}

	portBindings := container.NetworkSettings.Ports["7080/tcp"]
	if len(portBindings) == 0 {
		return ""
	}

	fmt.Println(portBindings)

	fmt.Println("Port:", portBindings[0].HostPort)
	return portBindings[0].HostPort
}

func DeleteContainerAndVolume(id string) error {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}

	conts, err := cli.ContainerList(context.Background(), container.ListOptions{})
	if err != nil {
		return err
	}

	var containerID string

	for _, container := range conts {
		if strings.Contains(container.Names[0], id) {
			containerID = container.ID
			break
		}
	}

	if containerID == "" {
		return nil
	}

	err = cli.ContainerRemove(context.Background(), containerID, container.RemoveOptions{Force: true,
		RemoveVolumes: true})
	if err != nil {
		return err
	}

	err = cli.NetworkRemove(context.Background(), id)
	if err != nil {
		return err
	}

	return nil
}

func Zip(src, target string) error {
	zipfile, err := os.Create(target)
	if err != nil {
		return err
	}
	defer zipfile.Close()

	archive := zip.NewWriter(zipfile)
	defer archive.Close()
	err = filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}

		header.Name = filepath.Join(filepath.Base(src), path[len(src):])

		if info.IsDir() {
			header.Name += "/"
		} else {
			header.Method = zip.Deflate
		}

		writer, err := archive.CreateHeader(header)
		if err != nil {
			return err
		}

		if !info.IsDir() {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()
			_, err = io.Copy(writer, file)
			if err != nil {
				return err
			}
		}
		return err
	})

	if err != nil {
		log.Printf("Error walking the path %v: %v\n", src, err)
	}
	return err
}
