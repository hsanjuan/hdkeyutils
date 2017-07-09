package hdwrap

import (
	"fmt"

	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrd/chaincfg/chainec"
	"github.com/decred/dcrutil"
	"github.com/decred/dcrutil/hdkeychain"
)

type DcrKey struct {
	key     *hdkeychain.ExtendedKey
	testnet bool
}

func (k *DcrKey) Type() KeyType {
	return Dcr
}

func (k *DcrKey) SetTestNet(b bool) {
	k.testnet = b
}

func (k *DcrKey) FromString(data string, priv bool) error {
	key, err := hdkeychain.NewKeyFromString(string(data))
	if err != nil {
		fmt.Println("herE")
		return err
	}

	if priv && !key.IsPrivate() {
		return fmt.Errorf("given key was not a private key")
	}

	k.key = key
	return nil
}

func (k *DcrKey) FromSeed(s Seed) error {
	params := &chaincfg.MainNetParams
	if k.testnet {
		params = &chaincfg.TestNet2Params
	}
	masterk, err := hdkeychain.NewMaster(s.Bytes(), params)
	if err != nil {
		return err
	}
	k.key = masterk
	return nil
}

func (k *DcrKey) GetMasterPub() (string, error) {
	pubk, err := k.key.Neuter()
	if err != nil {
		return "", err
	}

	return pubk.String()
}

func (k *DcrKey) GetMasterPriv() (string, error) {
	return k.key.String()
}

func (k *DcrKey) GetChildPrivKey(index int) (string, error) {
	childpriv, err := k.key.Child(uint32(index))
	if err != nil {
		return "", err
	}

	privk, err := childpriv.ECPrivKey()
	if err != nil {
		return "", err
	}

	params := &chaincfg.MainNetParams
	if k.testnet {
		params = &chaincfg.TestNet2Params
	}
	wif, err := dcrutil.NewWIF(privk, params, chainec.ECTypeSecp256k1)
	if err != nil {
		return "", err
	}

	return wif.String(), nil
}

func (k *DcrKey) GetChildPubKey(index int) (string, error) {
	childpub, err := k.key.Child(uint32(index))
	if err != nil {
		return "", err
	}

	params := &chaincfg.MainNetParams
	if k.testnet {
		params = &chaincfg.TestNet2Params
	}

	addr, err := childpub.Address(params)
	if err != nil {
		return "", err
	}
	return addr.EncodeAddress(), nil
}
