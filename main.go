package main

import (
	"github.com/nzhl/mysocks/client"
)

func main() {
	client := client.New()
	client.Listen()
}
