package util

import "github.com/getkin/kin-openapi/openapi3"

func appendTagsInOperation(op *openapi3.Operation, m map[string]bool) map[string]bool {
	if op == nil {
		return m
	}
	for _, t := range op.Tags {
		m[t] = true
	}
	return m
}

func UniquePathTags(swagger *openapi3.T) []string {
	m := make(map[string]bool)
	for _, v := range swagger.Paths {
		m = appendTagsInOperation(v.Get, m)
		m = appendTagsInOperation(v.Post, m)
		m = appendTagsInOperation(v.Put, m)
		m = appendTagsInOperation(v.Patch, m)
	}
	var u []string
	for t, _ := range m {
		u = append(u, t)
	}
	return u
}
