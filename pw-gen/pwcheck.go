package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/iegomez/mosquitto-go-auth/common"
)

// saltSize defines the salt size

func main() {

	var pkdf2 = flag.String("h", "", "pbkdf2 password hash")
	var password = flag.String("p", "", "password to compare with")

	flag.Parse()

	isEqual := common.HashCompare(*password, *pkdf2)
	if (isEqual) {
		fmt.Println("True")
	} else {
		fmt.Println("False")
        os.Exit(1)
	}
}
