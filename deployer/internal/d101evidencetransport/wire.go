package d101evidencetransport

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"unicode/utf8"

	"opensamguk-deployer/internal/d101custody"
)

func decodeExact(wire []byte, target any, maxBytes int) error {
	if len(wire) == 0 || len(wire) > maxBytes || !utf8.Valid(wire) || rejectDuplicates(wire) != nil || exactShape(wire, reflect.TypeOf(target).Elem()) != nil {
		return d101custody.ErrUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return d101custody.ErrUnavailable
	}
	return nil
}

func exactShape(wire []byte, shape reflect.Type) error {
	if bytes.Equal(bytes.TrimSpace(wire), []byte("null")) {
		return d101custody.ErrUnavailable
	}
	switch shape.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if json.Unmarshal(wire, &fields) != nil || len(fields) != shape.NumField() {
			return d101custody.ErrUnavailable
		}
		for i := 0; i < shape.NumField(); i++ {
			field := shape.Field(i)
			value, ok := fields[field.Tag.Get("json")]
			if !ok || exactShape(value, field.Type) != nil {
				return d101custody.ErrUnavailable
			}
		}
	case reflect.Map:
		var fields map[string]json.RawMessage
		if json.Unmarshal(wire, &fields) != nil {
			return d101custody.ErrUnavailable
		}
		for _, value := range fields {
			if exactShape(value, shape.Elem()) != nil {
				return d101custody.ErrUnavailable
			}
		}
	case reflect.Slice, reflect.Array:
		var values []json.RawMessage
		if json.Unmarshal(wire, &values) != nil {
			return d101custody.ErrUnavailable
		}
		for _, value := range values {
			if exactShape(value, shape.Elem()) != nil {
				return d101custody.ErrUnavailable
			}
		}
	}
	return nil
}

func rejectDuplicates(wire []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(wire))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for decoder.More() {
					name, err := decoder.Token()
					key, ok := name.(string)
					if err != nil || !ok || seen[key] {
						return d101custody.ErrUnavailable
					}
					seen[key] = true
					if err := walk(); err != nil {
						return err
					}
				}
			case '[':
				for decoder.More() {
					if err := walk(); err != nil {
						return err
					}
				}
			default:
				return d101custody.ErrUnavailable
			}
			_, err = decoder.Token()
			return err
		}
		return nil
	}
	if walk() != nil {
		return d101custody.ErrUnavailable
	}
	if _, err := decoder.Token(); err != io.EOF {
		return d101custody.ErrUnavailable
	}
	return nil
}
