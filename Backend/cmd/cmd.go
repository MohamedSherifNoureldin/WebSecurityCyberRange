package cmd

import (
	"cyberrange/db"
	"cyberrange/server"

	"github.com/joho/godotenv"
)

func init() {
	err := godotenv.Load(".env")
	if err != nil {
		panic(err)
	}

}
func Start() error {
	err := db.ConnDB()
	if err != nil {
		return err
	}

	err = server.StartServer()
	if err != nil {
		return err
	}

	return nil
}
