// Package base64ext provides strict base64 decoding that rejects whitespace.
package base64ext

import (
	"encoding/base64"
	"errors"
	"strings"
)

// ErrInvalidCharacter is returned when the input contains \r or \n.
var ErrInvalidCharacter = errors.New("base64ext: invalid character")

// DecodeString decodes a base64 string using strict decoding and rejects
// any input containing \r or \n characters.
func DecodeString(s string) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, ErrInvalidCharacter
	}
	return base64.StdEncoding.Strict().DecodeString(s)
}
