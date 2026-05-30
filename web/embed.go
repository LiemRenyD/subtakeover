package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed templates/*
var files embed.FS

// FS returns the embedded filesystem for web templates.
func FS() http.FileSystem {
	sub, err := fs.Sub(files, "templates")
	if err != nil {
		panic("failed to load templates: " + err.Error())
	}
	return http.FS(sub)
}
