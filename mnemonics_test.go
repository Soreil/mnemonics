package mnemonic

import "testing"

func init() {
	err := SetSalt(`heewiuhfiuwhfiwuhfeiuhellorewrhwiuehrwiuhiuweh`)
	if err != nil {
		panic(err)
	}
}

func TestSaltLength(T *testing.T) {
	salts := []struct {
		salt     string
		length   int
		expected bool
	}{
		{"heewiuhfiuwhfiwuhfeiuhellorewrhwiuehrwiuhiuweh", 40, true},
		{"wuhfeiuhellorewrhwiuehrwiuhiuweh", 40, false},
	}
	for _, v := range salts {
		SetSaltLength(v.length)
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
		ip, err := ip(v.ip)
		if v.valid {
			if err != nil {
				T.Fatal(err, ip)
			}
		} else {
			if err == nil {
				T.Fatal(err, ip)
			}
		}
	}
}

func TestMnemonic(T *testing.T) {
	testMnemonics := []struct {
		salt     string
		expected string
		input    string
		valid    bool
	}{
		//{"heewiuhfiuwhfiwuhfeiuhellorewrhwiuehrwiuhiuweh", "pisimomi", "100.20.100.80", true},  //Original
		//{"hewiuhfiuwhfiwuhfeiuhellorewrhwiuehrwiuhiuweh", "pisimomi", "100.20.100.80", false},  //Wrong salt
		//{"heewiuhfiuwhfiwuhfeiuhellorewrhwiuehrwiuhiuweh", "pisimomi", "100.20.100.80", false}, //Wrong expected
		//{"heewiuhfiuwhfiwuhfeiuhellorewrhwiuehrwiuhiuweh", "pisimomi", "100.20.100.8", false},  //Wrong IP
		//{"osaosifjwoijwaoijfoiwajfoiwjfoiwjfoiwjfoiwejfwoeijf",
		//	"p'huzityi",
		//	"2001:0db8:85a3:0000:0000:8a2e:0370:7334",
		//	true}, //ipv6 sample
		//{"osaosifjwoijwaoijfoiwajfoiwjfoiwjfoiwjfoiwejfwoeijf",
		//	"p'huzityi",
		//	"2001:0db8:85a3:0000:0000:8a2e:a370:7334",
		//	false}, //Wrong IPv6
		//{"osaosifjwoijwaoijfoiwajfoiwjfoiwjfoiwjfoiwejfwoeijf",
		//	"p'huzityw",
		//	"2001:0db8:85a3:0000:0000:8a2e:0370:7334",
		//	false}, //Wrong mnemonic
		//{"osaosifjwoiwaoijfoiwajfoiwjfoiwjfoiwjfoiwejfwoeijf",
		//	"p'huzityi",
		//	"2001:0db8:85a3:0000:0000:8a2e:0370:7334",
		//	false}, //Wrong Salt
		//{"osaosifjwoijwaoijfoiwajfoiwjfoiwjfoiwjfoiwejfwoeijf",
		//	"p'huzityi",
		//	"2001:0db8:85a3:0000:0000:8a2e:0370:7334",
		//	true}, //Wrong expected
		//{"LALALALALALALALALALALALALALALALALALALALA",
		//	"chidyietya",
		//	"194.213.253.159",
		//	false}, //Meguca test EXTERNAL ADDRESS
		//{"LALALALALALALALALALALALALALALALALALALALA",
		//	"chidyietya",
		//	"127.0.0.1",
		//	true}, //Meguca test INTERNAL ADDRESS
		{"1test2test3test4test5test6test7test8test",
			"pidugufi", //ch'ridyama on C++
			"127.0.0.1",
			true},
	}
	for _, v := range testMnemonics {
		SetSaltLength(40)
		err := SetSalt(v.salt)
		if err != nil {
			panic(err)
		}
		res, err := Mnemonic(v.input)
		if v.valid && err == nil {
			if v.expected == res {
			} else {
				T.Fatal(v, res, err)
			}
		} else if !v.valid && err != nil {
			if v.expected == res {
			} else {
				T.Fatal(v, res, err)
			}
		}
		T.Log(res)
	}
}
