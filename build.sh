#!/usr/bin/env bash


GOOS=linux GOARCH=amd64 go build -o bin/sm2tool-linux-amd64
GOOS=windows GOARCH=amd64 go build -o bin/sm2tool-windows-amd64.exe
GOOS=darwin GOARCH=amd64 go build -o bin/sm2tool-darwin-amd64
GOOS=darwin GOARCH=arm64 go build -o bin/sm2tool-darwin-arm64