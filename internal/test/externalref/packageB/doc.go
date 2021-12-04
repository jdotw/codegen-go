package packageB

//go:generate go run github.com/12kmps/codegen-go/cmd/oapi-codegen -generate types,skip-prune,spec --package=packageB -o externalref.gen.go spec.yaml
