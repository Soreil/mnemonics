package mnemonic

import (
	"io/ioutil"
	"strings"
	"testing"
)

func init() {
	err := SetSalt(`heewiuhfiuwhfiwuhfeiuhellorewrhwiuehrwiuhiuweh`)
	if err != nil {
		panic(err)
	}
}

func TestSaltLength(T *testing.T) {
	salts := []struct {
		salt     string
		expected bool
	}{
		{"heewiuhfiuwhfiwuhfeiuhellorewrhwiuehrwiuhiuweh", true},
		{"wuhfeiuhellorewrhwiuehrwiuhiuweh", false},
	}
	for _, v := range salts {
		err := SetSalt(v.salt)
		if err != nil {
			if v.expected == false {
			} else {
				T.Fatal(err)
			}
		} else {
			if v.expected == true {
			} else {
				T.Fatal("Salt should have have for length but didn't")
			}
		}
	}

}

func TestIp(T *testing.T) {
	testIps := []struct {
		ip    string
		valid bool
	}{
		{"Meguca", false},
		{"257.0.0.0", false},
		{"0.0.0.257", false},
		{"0.0.10.0", true},
		{"0.0.0.0", true},
		{"255.255.255.255", true},
		{"10.20.100", false},
	}
	for _, v := range testIps {
		err := validIp(v.ip)
		if v.valid {
			if err != nil {
				T.Fatal(err, v.ip)
			}
		} else {
			if err == nil {
				T.Fatal(err, v.ip)
			}
		}
	}
}

type inputCase struct {
	expected string
	input    string
	valid    bool
}

func TestMnemonic(T *testing.T) {
	testMnemonics := struct {
		salt  string
		cases []inputCase
	}{salt: "r088PUX0qpUjhUyZby6e4pQcDh3zzUQUpeLOy7Hb"}

	err := SetSalt(testMnemonics.salt)
	if err != nil {
		panic(err)
	}
	testMnemonics.cases = append(testMnemonics.cases, readCases("mnemonics_out")...)

	for _, test := range testMnemonics.cases {
		res, err := Mnemonic(test.input)
		if test.valid && err == nil {
			if test.expected == res {
			} else {
				T.Fatalf("%v, %s, %v\n", test, res, err)
			}
		} else if !test.valid && err != nil {
			if test.expected == res {
			} else {
				T.Fatalf("%v, %s, %v\n", test, res, err)
			}
		}
		T.Log(test)
	}
}

func readCases(fileName string) (cases []inputCase) {
	file, err := ioutil.ReadFile(fileName)
	if err != nil {
		panic(err)
	}
	lines := strings.Split(string(file), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		err := validIp(fields[0])
		if err != nil {
			panic(err)
		}
		cases = append(cases, inputCase{expected: fields[1], input: fields[0], valid: true})
	}
	return
}
