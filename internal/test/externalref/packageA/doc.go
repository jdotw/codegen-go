package packageA

//go:generate go run github.com/12kmps/codegen-go/cmd/oapi-codegen -generate types,skip-prune,spec --package=packageA -o externalref.gen.go --import-mapping=../packageB/spec.yaml:github.com/12kmps/codegen-go/internal/test/externalref/packageB spec.yaml
