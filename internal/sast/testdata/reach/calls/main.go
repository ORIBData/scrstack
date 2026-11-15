package main

import (
	"fmt"

	"golang.org/x/text/language"
)

func main() {
	tag, _, err := language.ParseAcceptLanguage("en-US")
	fmt.Println(tag, err)
}
