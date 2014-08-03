package solitaire

import (
	"bytes"
	"fmt"
	"regexp"
	"testing"
)

var invalidChars = regexp.MustCompile(`[^a-zA-Z]`)

// Test vectors
var testVectors = []struct {
	pt  string // Plaintext
	ct  string // Ciphertext
	key string // Key (passphrase)
}{
	// Default tests (Source: https://www.schneier.com/code/sol-test.txt)
	{"AAAAAAAAAAAAAAA", "EXKYI ZSGEH UNTIQ", ""},
	{"AAAAAAAAAAAAAAA", "XYIUQ BMHKK JBEGY", "f"},
	{"AAAAAAAAAAAAAAA", "TUJYM BERLG XNDIW", "fo"},
	{"AAAAAAAAAAAAAAA", "ITHZU JIWGR FARMW", "foo"},
	{"AAAAAAAAAAAAAAA", "XODAL GSCUL IQNSC", "a"},
	{"AAAAAAAAAAAAAAA", "OHGWM XXCAI MCIQP", "aa"},
	{"AAAAAAAAAAAAAAA", "DCSQY HBQZN GDRUT", "aaa"},
	{"AAAAAAAAAAAAAAA", "XQEEM OITLZ VDSQS", "b"},
	{"AAAAAAAAAAAAAAA", "QNGRK QIHCL GWSCE", "bc"},
	{"AAAAAAAAAAAAAAA", "FMUBY BMAXH NQXCJ", "bcd"},
	{"AAAAAAAAAAAAAAAAAAAAAAAAA", "SUGSR SXSWQ RMXOH IPBFP XARYQ", "cryptonomicon"},
	{"SOLITAIRE", "KIRAK SFJAN", "cryptonomicon"},

	// Distribution test
	{"ABCDEFGHIJKLMNOPQRSTUVWXYZ", "EYMBM EYNMQ EYFVE KLJQD UUTWG CMTPJ", ""},
	{"ABCDEFGHIJKLMNOPQRSTUVWXYZ", "EHZXE QOZQX HHKDG WKESR DVHAV LMXVZ", "foobarbaz"},

	// Padding test
	{"A", "EUHVF", ""},
	{"??A?", "EUHVF", ""},
	{"A", "IQEWR", "foo"},
}

func TestEncrypt(t *testing.T) {
	for i, v := range testVectors {
		// pt, ct, key := v[0], v[1], v[2]
		ct := invalidChars.ReplaceAllString(v.ct, "")
		output := Encrypt([]byte(v.pt), []byte(v.key))

		if !bytes.Equal(output, []byte(ct)) {
			t.Errorf("#%d: Encrypt(%q, %q) returns %q (expecting %q)",
				i+1, v.pt, v.key, output, ct)
		}
	}
}

func TestDecrypt(t *testing.T) {
	for i, v := range testVectors {
		// pt, ct, key := v[0], v[1], v[2]
		pt := invalidChars.ReplaceAllString(v.pt, "")
		output := Decrypt([]byte(v.ct), []byte(v.key))

		if len(output)%5 > 0 || !bytes.HasPrefix(output, []byte(pt)) {
			t.Errorf("#%d: Decrypt(%q, %q) returns %q (expecting %q)",
				i+1, v.ct, v.key, output, pt)
		}
	}
}

func ExampleEncrypt() {
	output := Encrypt([]byte("SOLITAIRE"), []byte("CRYPTONOMICON"))
	fmt.Printf("%s\n", output)
	// Output: KIRAKSFJAN
}

func ExampleDecrypt() {
	output := Decrypt([]byte("KIRAKSFJAN"), []byte("CRYPTONOMICON"))
	fmt.Printf("%s\n", output)
	// Output: SOLITAIREX
}
