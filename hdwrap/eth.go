package hdwrap

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// EthKey works much like a BtcKey except for public address generation
type EthKey struct {
	key     *BtcKey
	testnet bool
}

func (k *EthKey) Type() KeyType {
	return Eth
}

func (k *EthKey) SetTestNet(b bool) {
	k.testnet = b
	k.key.SetTestNet(b)
}

func (k *EthKey) FromString(data string, priv bool) error {
	k.key = &BtcKey{}
	return k.key.FromString(data, priv)
}

func (k *EthKey) FromSeed(s Seed) error {
	k.key = &BtcKey{}
	return k.key.FromSeed(s)
}

func (k *EthKey) GetMasterPub() (string, error) {
	return k.key.GetMasterPub()
}

func (k *EthKey) GetMasterPriv() (string, error) {
	return k.key.GetMasterPriv()
}

func (k *EthKey) GetChildPrivKey(index int) (string, error) {
	privk, err := k.key.GetChildPrivKeyBtc(index)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", privk.Serialize()), nil
}

func (k *EthKey) GetChildPubKey(index int) (string, error) {
	ecpub, err := k.key.GetChildPubKeyBtc(index)
	if err != nil {
		return "", err
	}

	if k.testnet {
		return encodeEthereumPubkey(ecpub), nil
	}

	return encodeEthereumPubkey(ecpub), nil
}

func encodeEthereumPubkey(k *btcec.PublicKey) string {
	addr := ethcrypto.PubkeyToAddress(*k.ToECDSA())
	return addr.Hex()
}
