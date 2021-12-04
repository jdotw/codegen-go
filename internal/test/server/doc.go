package server

//go:generate go run github.com/12kmps/codegen-go/cmd/oapi-codegen --generate=types,chi-server --package=server -o server.gen.go ../test-schema.yaml
//go:generate go run github.com/matryer/moq -out server_moq.gen.go . ServerInterface
