package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

var errObject = errors.New("invalid JSON object")

func Decode(raw []byte, dest any) error {
	schema := reflect.TypeOf(dest)
	if schema == nil || schema.Kind() != reflect.Pointer || schema.Elem().Kind() != reflect.Struct || !utf8.Valid(raw) {
		return errObject
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return errObject
	}
	if err := walk(decoder, '{', 0, fields(schema.Elem())); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errObject
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(dest)
}

func fields(schema reflect.Type) map[string]bool {
	keys := make(map[string]bool)
	for _, field := range reflect.VisibleFields(schema) {
		if field.Anonymous || !field.IsExported() {
			continue
		}
		key, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if key == "" {
			key = field.Name
		}
		if key != "-" {
			keys[key] = true
		}
	}
	return keys
}

func walk(decoder *json.Decoder, group json.Delim, depth int, allowed map[string]bool) error {
	if depth > 64 {
		return errObject
	}
	var seen map[string]bool
	if group == '{' {
		seen = make(map[string]bool)
	}
	for decoder.More() {
		if seen != nil {
			token, err := decoder.Token()
			key, ok := token.(string)
			if err != nil || !ok || seen[key] || allowed != nil && !allowed[key] {
				return errObject
			}
			seen[key] = true
		}
		token, err := decoder.Token()
		if err != nil {
			return errObject
		}
		if delim, ok := token.(json.Delim); ok {
			if err := walk(decoder, delim, depth+1, nil); err != nil {
				return err
			}
		}
	}
	_, err := decoder.Token()
	return err
}
