package core

import (
	"math/big"

	"github.com/iden3/go-iden3-crypto/babyjub"
)

// encapsulates different forms of keys derived from the same
// private key
type KeyEntry struct {
	PrivateKey       *babyjub.PrivateKey
	PublicKey        *babyjub.PublicKey
	PrivateKeyForZkp *big.Int
}
