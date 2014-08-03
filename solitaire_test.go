package solitaire

import (
	"bytes"
	"fmt"
	"testing"
	"regexp"
)

var invalidChars = regexp.MustCompile(`[^a-zA-Z]`)


// Test vectors. Source: https://www.schneier.com/code/sol-test.txt
// Format: [[plaintext, ciphertext, key], ...]
var testVectors = [][]string{
	[]string{"AAAAAAAAAAAAAAA", "EXKYI ZSGEH UNTIQ", ""},
	[]string{"AAAAAAAAAAAAAAA", "XYIUQ BMHKK JBEGY", "f"},
	[]string{"AAAAAAAAAAAAAAA", "TUJYM BERLG XNDIW", "fo"},
	[]string{"AAAAAAAAAAAAAAA", "ITHZU JIWGR FARMW", "foo"},
	[]string{"AAAAAAAAAAAAAAA", "XODAL GSCUL IQNSC", "a"},
	[]string{"AAAAAAAAAAAAAAA", "OHGWM XXCAI MCIQP", "aa"},
	[]string{"AAAAAAAAAAAAAAA", "DCSQY HBQZN GDRUT", "aaa"},
	[]string{"AAAAAAAAAAAAAAA", "XQEEM OITLZ VDSQS", "b"},
	[]string{"AAAAAAAAAAAAAAA", "QNGRK QIHCL GWSCE", "bc"},
	[]string{"AAAAAAAAAAAAAAA", "FMUBY BMAXH NQXCJ", "bcd"},
	[]string{"AAAAAAAAAAAAAAAAAAAAAAAAA", "SUGSR SXSWQ RMXOH IPBFP XARYQ", "cryptonomicon"},
	[]string{"SOLITAIRE", "KIRAK SFJAN", "cryptonomicon"},

	// // Distribution test
	[]string{"ABCDEFGHIJKLMNOPQRSTUVWXYZ", "EYMBM EYNMQ EYFVE KLJQD UUTWG CMTPJ", ""},
	[]string{"ABCDEFGHIJKLMNOPQRSTUVWXYZ", "EHZXE QOZQX HHKDG WKESR DVHAV LMXVZ", "foobarbaz"},

	// // Padding test
	[]string{"A", "EUHVF", ""},
	[]string{"??A?", "EUHVF", ""},
	[]string{"A", "IQEWR", "foo"},
}

func TestEncrypt(t *testing.T) {
	for i, v := range testVectors {
		pt, ct, key := v[0], v[1], v[2]
		output := Encrypt([]byte(pt), []byte(key))
		ct = invalidChars.ReplaceAllString(ct, "")

		if !bytes.Equal(output, []byte(ct)) {
			t.Errorf("#%d: Encrypt(%q, %q) returns %q (expecting %q)",
			i+1, pt, key, output, ct)
		}
	}
}

func TestDecrypt(t *testing.T) {
	for i, v := range testVectors {
		pt, ct, key := v[0], v[1], v[2]
		pt = invalidChars.ReplaceAllString(pt, "")
		output := Decrypt([]byte(ct), []byte(key))

		if len(output) % 5 > 0 || !bytes.HasPrefix(output, []byte(pt)) {
			t.Errorf("#%d: Decrypt(%q, %q) returns %q (expecting %q)",
			i+1, ct, key, output, pt)
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
