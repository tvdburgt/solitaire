// Package solitaire implements the Solitaire encryption algorithm by Bruce
// Schneier. For more information, see: https://www.schneier.com/solitaire.html
package solitaire

import (
	"fmt"
)

const (
	suitCount = 4             // Number of suit types (excluding joker)
	suitSize  = 13            // Number of cards per suit
	charSize  = 'Z' - 'A' + 1 // A-Z range
)

// Suit value represents base value of card (in increments of SuitSize)
const (
	clubs suit = suitSize * iota
	diamonds
	hearts
	spades

	joker suit = (iota * suitSize) + 1
)

const (
	jokerA = iota
	jokerB
)

var suits = []suit{clubs, diamonds, hearts, spades}

type suit int

type card struct {
	suit suit
	rank int
}

func (c *card) String() string {
	if c.suit == joker {
		switch c.rank {
		case jokerA:
			return "A"
		case jokerB:
			return "B"
		default:
			return "?"
		}
	} else {
		return fmt.Sprintf("%d", c.value())
	}
}

func (c *card) value() int {
	if c.suit == joker {
		return int(c.suit)
	} else {
		return int(c.suit) + c.rank
	}
}

// Returns 0-based character index (based on card's value)
func (c *card) number() byte {
	return byte((c.value() - 1) % charSize)
}

type deck []*card

// Creates deck of cards with default ordering.
func newDeck() *deck {
	d := make(deck, 0, suitSize*suitCount+2)

	// Add regular cards
	for _, s := range suits {
		for i := 1; i <= suitSize; i++ {
			d = append(d, &card{s, i})
		}
	}

	// Add two jokers
	d = append(d, &card{joker, jokerA})
	d = append(d, &card{joker, jokerB})

	// for _, c := range deck.cards {
	// 	fmt.Printf("%s, %d, %d\n", c, c.Value(), c.Number())
	// }
	return &d
}

// Returns index of the specified joker card in this deck
func (d deck) jokerIndex(rank int) int {
	for i, c := range d {
		if c.suit == joker && c.rank == rank {
			return i
		}
	}
	return -1
}

// Moves card at index i to j (j wraps around and skips bottom card)
func (d deck) move(i, j int) {
	// Recalculate index
	if j >= len(d) {
		j = (j % len(d)) + 1
	}

	// Just swap for adjacent cards
	if j-i == 1 || j-i == -1 {
		d[i], d[j] = d[j], d[i]
		return
	}

	// Remove card at i
	card := d[i]
	d = append(d[:i], d[i+1:]...)

	// Insert card at j
	d = append(d, nil)
	copy(d[j+1:], d[j:])
	d[j] = card
}

// Performs a count cut (step 4) at index i
func (dp *deck) cut(i int) deck {
	d := *dp
	s := make(deck, len(d))     // Create empty deck
	copy(s, d[i:])              // Copy top segment
	copy(s[len(s)-i-1:], d[:i]) // Copy bottom segment
	s[len(s)-1] = d[len(d)-1]   // Bottom card stays in place
	*dp = s                     // Change pointer to new deck
	return s
}

// Generates a single output card
func (dp *deck) cycle(n int) (output *card) {

	d := *dp

	// fmt.Println("0:", dp)

	// Step 1: move A one card down
	// 1 2 3 4 ... 52 A B
	// 1 2 3 4 ... 52 B A
	a := dp.jokerIndex(jokerA)
	dp.move(a, a+1)
	// fmt.Println("1:", dp)

	// Step 2: move B two cards down
	// 1 2 3 4 ... 52 B A
	// 1 B 2 3 4 ... 52 A
	b := dp.jokerIndex(jokerB)
	dp.move(b, b+2)
	// fmt.Println("2:", dp)

	// Step 3: perform triple cut
	// 1 B 2 3 4 ... 52 A
	// B 2 3 4 ... 52 A 1
	a, b = dp.jokerIndex(jokerA), dp.jokerIndex(jokerB)
	var top, bot, i int
	if a < b {
		top, bot = a, b
	} else {
		top, bot = b, a
	}
	s := make(deck, len(d))        // Create empty deck
	i += copy(s, d[bot+1:])        // Copy top segment
	i += copy(s[i:], d[top:bot+1]) // Copy middle segment
	i += copy(s[i:], d[:top])      // Copy bottom segment
	*dp, d = s, s
	// fmt.Println("3:", d)

	// Step 4: perform count cut
	// B 2 3 4 ... 52 A 1
	// 2 3 4 ... 52 A B 1
	i = d[len(d)-1].value() // Determine cut index from top card
	d = dp.cut(i)
	// fmt.Println("4:", dp)

	// If cut number is given, repeat step 4 with number and skip step 5
	if n > 0 {
		dp.cut(n)
		// fmt.Println("4:", dp)
		return
	}

	// Step 5: find output card
	value := d[0].value() // Get value of top card
	output = d[value]     // Determine output card (n steps from top)
	if output.suit == joker {
		return dp.cycle(n)
	}
	return
}

// Keys the deck by performing a deck cycle for each key character.
// Each cycle operation is extended with an additional count cut (based on
// character index of current character).
func (dp *deck) key(key []byte) {
	for _, c := range key {
		n := int(c - 'A' + 1) // Calculate 1-based index of character
		dp.cycle(n)
	}
}

// Pads data slice to nearest given multiple.
func pad(data []byte, multiple int, padChar byte) []byte {
	for len(data)%multiple > 0 {
		data = append(data, padChar)
	}
	return data
}

// Creates copy of data slice with illegal chars left out and all
// alphabetical chars converted to upper case.
func filter(data []byte) []byte {
	result := make([]byte, 0, len(data))
	for _, c := range data {
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		if c >= 'A' && c <= 'Z' {
			result = append(result, c)
		}
	}
	return result
}

// Encrypt encrypts plaintext with key using the Solitaire encryption algorithm.
// Illegal characters ([^a-zA-Z]) in both byte slice parameters are skipped.
// Lower case characters are automatically converted to upper case in order to
// comply with the input format for the encryption algorithm.
// The plaintext is padded with Xs before encryption takes place.
func Encrypt(plaintext, key []byte) []byte {
	data := filter(plaintext)
	data = pad(data, 5, 'X')
	deck := newDeck()
	output := make([]byte, len(data))

	deck.key(filter(key))

	for i, c := range data {
		card := deck.cycle(0)
		n := c - 'A'
		m := card.number()
		output[i] = 'A' + (n+m+1)%charSize
	}

	return output
}

// Decrypt decrypts ciphertext with key using the Solitaire encryption algorithm.
// Illegal key characters ([^a-zA-Z]) are skipped. Lower case key characters are
// automatically converted to upper case in order to comply with the input
// format for the encryption algorithm.
func Decrypt(ciphertext, key []byte) []byte {
	data := filter(ciphertext)
	deck := newDeck()
	output := make([]byte, len(data))

	deck.key(filter(key))

	for i, c := range data {
		card := deck.cycle(0)
		n := c - 'A'
		m := card.number()
		output[i] = 'A' + (n-m-1+charSize)%charSize
	}

	return output
}
