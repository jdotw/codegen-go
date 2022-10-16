#!/bin/sh

go run cmd/oapi-codegen/codegen.go -o test -generate bootstrap -cluster name ~/Source/project/api.yaml
