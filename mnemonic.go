package mnemonic

import (
	"crypto/sha1"
	"errors"
	"fmt"
	"net"
	"strconv"
)

//Top nibble
var mnemonicStarts [16]string

//Bottom nibble
var mnemonicEnds [16]string

const saltLength = 40

var salt string

func init() {
	mnemonicStarts = [16]string{"", "k", "s", "t", "d", "n", "h", "b", "p", "m", "f", "r", "g", "z", "l", "ch"}
	mnemonicEnds = [16]string{"a", "i", "u", "e", "o", "a", "i", "u", "e", "o", "ya", "yi", "yu", "ye", "yo", "'"}
	err := SetSalt("LALALALALALALALALALALALALALALALALALALALA")
	if err != nil {
		panic(err)
	}
}

// InvalidIPError indicates that the passed IP address is of invalid format
type InvalidIPError struct{ s string }

func (e InvalidIPError) Error() string {
	return "Not a valid IP address: " + e.s
}

func validIp(s string) error {
	ip := net.ParseIP(s)
	if ip == nil {
		return InvalidIPError{s}
	}
	if ip := ip.To4(); ip != nil {
		return nil
	}
	if ip := ip.To16(); ip != nil {
		return nil
	}
	return InvalidIPError{s}
}

func Mnemonic(addr string) (string, error) {
	err := validIp(addr)
	if err != nil {
		return "", err
	}
	salted := addr + salt
	out := sha1.Sum([]byte(salted))

	var result string
	for i := 0; i < 4; i++ {
		//This takes 4 bytes instead of 5, it looks that way in the C++!
		part := fmt.Sprintf("%x", out[i*5:((i+1)*5)-1])
		val, err := strconv.ParseUint(part, 16, 64)
		if err != nil {
			return "", err
		}
		result += mnemonicStarts[(val%256)/16] + mnemonicEnds[val%16]
	}
	return result, nil
}

func SetSalt(s string) error {
	if len([]byte(s)) < saltLength {
		return errors.New(fmt.Sprintf("Salt length %d not the same as recommended %d\n", len([]byte(s)), saltLength))
	}
	salt = s
	return nil
}
