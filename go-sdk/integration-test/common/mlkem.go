package common

import (
	"math/big"
	"testing"

	"github.com/iden3/go-rapidsnark/types"
	"github.com/stretchr/testify/assert"
)

func ExtractSharedSecretAndEncryptedValues(t *testing.T, proof *types.ZKProof) ([25]*big.Int, []*big.Int) {
	ssStrs := proof.PubSignals[:25]
	// convert the strings to big.Ints
	var ss [25]*big.Int
	for i, str := range ssStrs {
		v, ok := new(big.Int).SetString(str, 10)
		assert.True(t, ok, "Failed to convert hex string to big.Int")
		ss[i] = v
	}

	// use the recovered shared secret to decrypt the output ciphertexts
	encryptedValueStrs := proof.PubSignals[25:41]
	var encryptedValues []*big.Int
	for _, str := range encryptedValueStrs {
		v, ok := new(big.Int).SetString(str, 10)
		assert.True(t, ok, "Failed to convert hex string to big.Int")
		encryptedValues = append(encryptedValues, v)
	}

	return ss, encryptedValues
}
