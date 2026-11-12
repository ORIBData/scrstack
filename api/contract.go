package api

import (
	"embed"
	_ "embed"
)

// OpenAPI is the published API contract.
//
//go:embed openapi.yaml
var OpenAPI []byte

// Swagger contains the pinned, locally served Swagger UI distribution assets.
//
//go:embed swagger/*
var Swagger embed.FS
