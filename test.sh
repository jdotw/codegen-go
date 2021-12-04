#!/bin/sh

go run cmd/oapi-codegen/baas-codegen.go -o test -generate bootstrap ~/Source/12kmps/api-spec-templates/baas-templates/CustomerAccessEntitlement.yaml
