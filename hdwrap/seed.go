package hdwrap

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/decred/dcrwallet/walletseed"
)

// A Seed is just a byte slice with some utility functions attached.
type Seed []byte

// Generate produces a random 512-bit seed to be used for HD wallets.
// It uses Go's crypto.rand as source of randomness. randLen specifies
// how many bytes to read from the source, before performing a SHA512
// operation on it and returning the resulting 64 bytes.
func Generate(randLen int) (Seed, error) {
	h := sha512.New()
	randBytes := make([]byte, randLen)
	_, err := io.ReadFull(rand.Reader, randBytes)
	if err != nil {
		return nil, err
	}
	h.Write(randBytes)
	return h.Sum(nil), nil
}

// GenerateCustom produces a 512-bit seed using a provided source of
// randomness, and an additional user-defined slice of bytes. randLen specifies
// how many bytes to read from the source. The extraRand bytes are attached
// to it and then a SHA512 operation is performed before returning the resulting
// 64 bytes.
func GenerateCustom(randLen int, randSource io.Reader, extraRand []byte) (Seed, error) {
	h := sha512.New()
	randBytes := make([]byte, randLen)
	_, err := io.ReadFull(randSource, randBytes)
	if err != nil {
		return nil, err
	}
	h.Write(randBytes)
	h.Write(extraRand)
	return h.Sum(nil), nil
}

// NewSeedFromFile reads a hex-encoded Seed read from a file.
func NewSeedFromFile(path string) (Seed, error) {
	seedHexBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return NewSeedFromHex(seedHexBytes)
}

// NewSeedFromWords decodes a mnemonic-encoded seed. The input
// string must be a space-separated list of words.
func NewSeedFromWords(input string) (Seed, error) {
	return walletseed.DecodeUserInput(input)

}

// NewSeedFromHex decodes a hex-encoded seed and returns it.
func NewSeedFromHex(input []byte) (Seed, error) {
	seed := make([]byte, hex.DecodedLen(len(input)))
	_, err := hex.Decode(seed, input)
	if err != nil {
		return nil, err
	}
	return seed, nil
}

// NewSeedFromBytes just returns the given byte slice
// as a Seed.
func NewSeedFromBytes(b []byte) Seed {
	return b
}

// EncodeWords encodes the Seed as a mnemonic list of words.
func (s Seed) EncodeWords() []string {
	return walletseed.EncodeMnemonicSlice(s)
}

// EncodeHex encodes the Seed in hex format.
func (s Seed) EncodeHex() []byte {
	seedhex := make([]byte, hex.EncodedLen(len(s)))
	hex.Encode(seedhex, s)
	return seedhex
}

// String returns the EncodeWords() result, with all
// words joined by a space.
func (s Seed) String() string {
	return strings.Join(s.EncodeWords(), " ")
}

// Bytes returns the Seed as a byte slice.
func (s Seed) Bytes() []byte {
	return s
}

// Zero clears the values associated to the slice from the memory
func (s Seed) Zero() {
	// This is how hdkeychain clears bytes
	lens := len(s)
	for i := 0; i < lens; i++ {
		s[i] = 0
	}
}

// PrintMnenomic prints the EncodeWords() result.
// wordsPerLine specifies how many words should be printed
// before moving on to a new line.
func (s Seed) PrintMnemonic(wordsPerLine int) {
	if wordsPerLine <= 0 {
		panic("wordsPerLine must be >= 1")
	}

	for i, w := range s.EncodeWords() {
		fmt.Printf("%s", w)
		if (i+wordsPerLine+1)%wordsPerLine == 0 {
			fmt.Printf("\n")
		} else {
			fmt.Print(" ")
		}
	}
}

// WriteToFile writes a the hex-encoded representation of the Seed to a file.
// It will use 0600 permissions.
func (s Seed) WriteToFile(path string, overwrite bool) error {
	// If file does not exist or overwrite is true
	if _, err := os.Stat(path); os.IsNotExist(err) || overwrite {
		return ioutil.WriteFile(path, s.EncodeHex(), 0600)
	}

	return fmt.Errorf("file %s exists. No ovewrite action will be performed", path)
}
