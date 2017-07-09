// Package hdwrap provides an wrapper interface and implementations of HD wallet
// operations for different cryptocurrency keys.
package hdwrap

import "strings"

// Supported HD wallet key formats
const (
	Bad = iota
	Btc
	Zec
	Eth
	Dcr
)

// KeyType tracks supported Key formats.
type KeyType int

var keyTypeMap = map[string]KeyType{
	"btc": Btc,
	"zec": Zec,
	"eth": Eth,
	"dcr": Dcr,
}

// String returns the string representation of a KeyType
func (t KeyType) String() string {
	for k, v := range keyTypeMap {
		if v == t {
			return k
		}
	}
	panic("bad key type")
}

// A Key abstracts key formats from different cryptocurrencies
// allowing to perform HD wallet operations like deriving child keys
// while sharing the same seed for all HD wallet key formats.
type Key interface {
	Type() KeyType
	SetTestNet(b bool)
	FromSeed(s Seed) error
	FromString(data string, priv bool) error
	GetMasterPub() (string, error)
	GetMasterPriv() (string, error)
	GetChildPrivKey(index int) (string, error)
	GetChildPubKey(index int) (string, error)
}

// EmptyKey returns an unitialized Key given a KeyType.
func EmptyKey(t KeyType) Key {
	switch t {
	case Btc:
		return &BtcKey{}
	case Zec:
		return &ZecKey{}
	case Eth:
		return &EthKey{}
	case Dcr:
		return &DcrKey{}
	default:
		panic("bad key type")
	}
}

// EmptyKeyStr returns an unitialized Key given a KeyType string.
func EmptyKeyStr(t string) Key {
	return EmptyKey(keyTypeMap[strings.ToLower(t)])
}
