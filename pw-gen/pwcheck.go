package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/iegomez/mosquitto-go-auth/common"
)

func main() {

	var password = flag.String("p", "", "plain text password")
	var hashed = flag.String("h", "", "pbkdf2 password hash")

	flag.Parse()

	if (common.HashCompare(*password, *hashed)) {
		fmt.Println("success: plain and hashed passwords match")
        return
	}
	fmt.Println("error: plain and hashed passwords don't match")
    os.Exit(1)
}
