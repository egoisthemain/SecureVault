package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	if err != nil {
		os.Exit(1)
	}

	fmt.Println(hex.EncodeToString(secret))
}
