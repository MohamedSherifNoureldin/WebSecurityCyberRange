package main

import (
	"cyberrange/cmd"
)

func main() {
	err := cmd.Start()
	if err != nil {
		panic(err)
	}

}
