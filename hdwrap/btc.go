package hdwrap

import (
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/ripemd160"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/base58"
	"github.com/btcsuite/btcutil/hdkeychain"
)

// BtcKey implements the Key interface for a Bitcoin
// HDWallet.
type BtcKey struct {
	key     *hdkeychain.ExtendedKey
	testnet bool
}

func (k *BtcKey) Type() KeyType {
	return Btc
}

// SetTestNet allows producing keys for Bitcoin's TestNet3
func (k *BtcKey) SetTestNet(b bool) {
	k.testnet = b
}

// FromString initializes a BtcKey with by importing a Bitcoin HD wallet
// private or public key. They start with xpub... or xpriv...
func (k *BtcKey) FromString(data string, priv bool) error {
	key, err := hdkeychain.NewKeyFromString(string(data))
	if err != nil {
		return err
	}

	if priv && !key.IsPrivate() {
		return fmt.Errorf("given key was not a private key")
	}

	k.key = key
	return nil
}

// FromSeed initializes a BtcKey from a Seed. The seed is just a slice of
// of bytes (hopefully generated in a secure random fashion).
func (k *BtcKey) FromSeed(s Seed) error {
	params := &chaincfg.MainNetParams
	if k.testnet {
		params = &chaincfg.TestNet3Params
	}
	masterk, err := hdkeychain.NewMaster(s.Bytes(), params)
	if err != nil {
		return err
	}
	k.key = masterk
	return nil
}

// GetMasterPub returns the Bitcoin-formatted master public
// key (xpub...)
func (k *BtcKey) GetMasterPub() (string, error) {
	pubk, err := k.key.Neuter()
	if err != nil {
		return "", err
	}

	return pubk.String(), nil
}

// GetMasterPriv returns the Bitcoin-formatted private key
// (xpriv...)
func (k *BtcKey) GetMasterPriv() (string, error) {
	return k.key.String(), nil
}

// GetChildPrivKey derivates a private key from the master key
// and returns an Bitcoin-importable WIF-encoded version of it.
func (k *BtcKey) GetChildPrivKey(index int) (string, error) {
	privk, err := k.GetChildPrivKeyBtc(index)
	if err != nil {
		return "", err
	}

	params := &chaincfg.MainNetParams
	if k.testnet {
		params = &chaincfg.TestNet3Params
	}
	wif, err := btcutil.NewWIF(privk, params, true)
	if err != nil {
		return "", err
	}

	return wif.String(), nil
}

// GetChildPubKey derivates a public key from the master key
// and returns it formatted as a valid Bitcoin address.
func (k *BtcKey) GetChildPubKey(index int) (string, error) {
	ecpub, err := k.GetChildPubKeyBtc(index)
	if err != nil {
		return "", err
	}

	if k.testnet {
		return encodeBitcoinPubkey(ecpub, []byte{chaincfg.TestNet3Params.PubKeyHashAddrID}), nil
	}

	return encodeBitcoinPubkey(ecpub, []byte{chaincfg.MainNetParams.PubKeyHashAddrID}), nil
}

// GetChildPrivKeyBtc derivates a Bitcoin private key from the master key
// and returns it.
func (k *BtcKey) GetChildPrivKeyBtc(index int) (*btcec.PrivateKey, error) {
	childpriv, err := k.key.Child(uint32(index))
	if err != nil {
		return nil, err
	}

	privk, err := childpriv.ECPrivKey()
	if err != nil {
		return nil, err
	}
	return privk, nil
}

// GetChildPubKeyBtc derivates a Bitcoin public key from the master key
// and returns it.
func (k *BtcKey) GetChildPubKeyBtc(index int) (*btcec.PublicKey, error) {
	childpub, err := k.key.Child(uint32(index))
	if err != nil {
		return nil, err
	}

	ecpub, err := childpub.ECPubKey()
	if err != nil {
		return nil, err
	}

	return ecpub, nil
}

func encodeBitcoinPubkey(k *btcec.PublicKey, prefix []byte) string {
	comp := k.SerializeCompressed()
	shad := sha256.Sum256(comp)
	h := ripemd160.New()
	h.Write(shad[:])
	return base58Check(h.Sum(nil), prefix)
}

func base58Check(val, prefix []byte) string {
	val = append(prefix, val...)
	first := sha256.Sum256(val)
	chk := sha256.Sum256(first[:])
	return base58.Encode(append(val, chk[:4]...))
}
