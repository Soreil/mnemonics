package mnemonics

import (
	"crypto/sha1"
	"errors"
	"fmt"
	"net"
	"strconv"
)

type ipType int

const (
	ipV4 ipType = iota
	ipV6
	other
)

type ipError string

func (e ipError) Error() string {
	return string(e)
}

const (
	invalidIpV4 ipError = "Invalid IPv4 address"
	invalidIpV6 ipError = "Invalid IPv6 address"
	invalidIp   ipError = "Invalid IP address"
	notIp       ipError = "Not an IP address"
)

var mnemonicStarts [16]string
var mnemonicEnds [16]string
var saltLength int
var salt string

func init() {
	//TODO(sjon): Should these be user settable?
	mnemonicStarts = [16]string{"", "k", "s", "t", "d", "n", "h", "b", "p", "m", "f", "r", "g", "z", "l", "ch"}
	mnemonicEnds = [16]string{"a", "i", "u", "e", "o", "a", "i", "u", "e", "o", "ya", "yi", "yu", "ye", "yo", "'"}
	SetSaltLength(40)
	err := SetSalt(`jsdojfsoiajfoicwcoinweoijfoiwfdjwoifjwoifjf;akfj;pweiuwruw;eour;wajf;lksjflskj`)
	if err != nil {
		panic(err)
	}
}

func ip(s string) (net.IP, ipType, error) {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, other, invalidIp
	}
	if ip := ip.To4(); ip != nil {
		return ip, ipV4, nil
	}
	if ip := ip.To16(); ip != nil {
		return ip, ipV6, nil
	}
	return nil, other, invalidIp
}

func byteToHex(hashpart []byte, max int) string {
	var out []byte
	for i := 0; i < max/2; i++ {
		c := hashpart[i]
		out = strconv.AppendInt(out, int64(c>>4), 16)
		out = strconv.AppendInt(out, int64(c&15), 16)
	}
	return string(out)
}

func Mnemonic(addr string) (string, error) {
	ip, _, err := ip(addr)
	if err != nil {
		return "", err
	}
	salted := ip.String() + salt
	out := sha1.Sum([]byte(salted))

	var result string
	for i := 0; i < 4; i++ {
		part := byteToHex(out[i*5:], 8)
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
		return errors.New(fmt.Sprintf("Salt length %d smaller than recommended %d\n", len([]byte(s)), saltLength))
	}
	salt = s
	return nil
}

func SetSaltLength(n int) {
	saltLength = n
}
