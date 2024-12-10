package server

import (
	"errors"
	"net/http"
	"os"

	"cyberrange/server/handlers/admin"
	"cyberrange/server/handlers/auth"
	"cyberrange/server/handlers/shared"
	"cyberrange/server/handlers/user"

	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func StartServer() error {
	e := echo.New()

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		Skipper:      middleware.DefaultSkipper,
		AllowOrigins: []string{"*"},
		AllowMethods: []string{http.MethodGet, http.MethodDelete, http.MethodPut, http.MethodPost}}))

	e.Use(middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(30)))
	e.Use(middleware.Recover())

	api := e.Group("/api/v1")

	api.GET("/health", func(c echo.Context) error {
		return c.String(200, "I'm Good Bro, Thanks for checking you are a real one <3")
	})
	api.GET("/terminal", shared.Terminal)
	api.POST("/contact-us", user.Contactus)

	authGroup := api.Group("/auth")
	authGroup.POST("/login", auth.Login)
	authGroup.POST("/register", auth.Register)
	authGroup.POST("/register-admin", auth.RegisterAdmin)
	authGroup.POST("/forget-password", auth.ForgetP)
	authGroup.POST("/change-password", auth.ChangePass)

	sharedGroup := api.Group("/shared")
	sharedGroup.Use(echojwt.JWT([]byte(os.Getenv("JWT_SECRET"))))
	sharedGroup.GET("/get-labs", shared.GetLabs)
	sharedGroup.GET("/get-jeopardyctf", shared.GetJeopardyCTF)
	sharedGroup.GET("/get-attack-defensectf", shared.GetAttackDefenseCTF)
	//sharedGroup.POST("/run-lab", shared.RunLab)
	sharedGroup.GET("/download-attachment", shared.DownloadAttachment)
	sharedGroup.POST("/submit-flag", user.SubmitFlag)
	//sharedGroup.POST("/submit-lab-flag", shared.SubmitLabFlag)
	sharedGroup.GET("/download-all", shared.DownloadAll)
	sharedGroup.GET("/is-admin", shared.IsAdmin)
	sharedGroup.GET("/get-scoreboard", shared.GetScoreboard)
	sharedGroup.DELETE("/delete-account", shared.DeleteAccount)
	sharedGroup.PUT("/update-account", shared.UpdateAccount)
	sharedGroup.GET("/get-categories", shared.GetCategories)
	sharedGroup.PUT("/submit-ctf-image", shared.SubmitCTFImage)
	sharedGroup.GET("/start-attack", shared.StartTheAttack)

	adminGroup := api.Group("/admin")
	adminGroup.Use(echojwt.JWT([]byte(os.Getenv("JWT_SECRET"))))
	adminGroup.POST("/add-lab", admin.AddLab)
	adminGroup.GET("/get-users", admin.GetUsers)
	adminGroup.DELETE("/delete-lab", admin.DeleteLab)
	adminGroup.POST("/make-admin", admin.MakeAdmin)
	adminGroup.DELETE("/delete-user", admin.DeleteUser)
	adminGroup.POST("/add-challenge", admin.AddChallenge)
	adminGroup.DELETE("/delete-challenge", admin.DeleteChallenge)
	adminGroup.GET("/get-settings", admin.GetSettings)
	adminGroup.POST("/save-settings", admin.SaveSettings)
	adminGroup.GET("/get-challenges", admin.GetChallenges)
	adminGroup.GET("/feedback", admin.GetFeedbacks)
	adminGroup.POST("/add-category", admin.AddCategory)
	adminGroup.DELETE("/delete-category", admin.DeleteCategory)
	adminGroup.GET("/usage", admin.GetUsage)
	adminGroup.PUT("/update-lab-status", admin.UpdateLabStatus)

	userGroup := api.Group("/user")
	userGroup.Use(echojwt.JWT([]byte(os.Getenv("JWT_SECRET"))))
	userGroup.POST("/feedback", user.SendFeedback)

	port := os.Getenv("PORT")
	env := os.Getenv("ENV")

	if env == "DEV" {
		err := e.Start(":" + port)
		if err != nil {
			return err
		}
	} else if env == "PROD" {
		err := e.StartTLS(":"+port, "/CyberRange/fullchain.pem", "/CyberRange/privkey.pem")
		if err != nil {
			return err
		}
	} else {
		return errors.New("Invalid environment variable, please set it to DEV or PROD")
	}

	return nil
}
