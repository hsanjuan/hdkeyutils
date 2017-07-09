package hdwrap

import "github.com/btcsuite/btcd/btcec"

var ZcashPrefix = []byte{0x1c, 0xb8}
var ZcashP2SHPrefix = []byte{0x1c, 0xbd}
var ZcashTestnetPrefix = []byte{0x1d, 0x25}
var ZcashTestnetP2SHPrefix = []byte{0x1c, 0xba}

// ZecKey works much like a BtcKey except for public address generation
type ZecKey struct {
	key     *BtcKey
	testnet bool
}

func (k *ZecKey) Type() KeyType {
	return Zec
}

func (k *ZecKey) SetTestNet(b bool) {
	k.testnet = b
	k.key.SetTestNet(b)
}

func (k *ZecKey) FromString(data string, priv bool) error {
	k.key = &BtcKey{}
	return k.key.FromString(data, priv)
}

func (k *ZecKey) FromSeed(s Seed) error {
	k.key = &BtcKey{}
	return k.key.FromSeed(s)
}

func (k *ZecKey) GetMasterPub() (string, error) {
	return k.key.GetMasterPub()
}

func (k *ZecKey) GetMasterPriv() (string, error) {
	return k.key.GetMasterPriv()
}

func (k *ZecKey) GetChildPrivKey(index int) (string, error) {
	return k.key.GetChildPrivKey(index)
}

func (k *ZecKey) GetChildPubKey(index int) (string, error) {
	ecpub, err := k.key.GetChildPubKeyBtc(index)
	if err != nil {
		return "", err
	}

	if k.testnet {
		return encodeZcashPubkey(ecpub, ZcashTestnetPrefix), nil
	}

	return encodeZcashPubkey(ecpub, ZcashPrefix), nil
}

func encodeZcashPubkey(k *btcec.PublicKey, prefix []byte) string {
	return encodeBitcoinPubkey(k, prefix)
}
