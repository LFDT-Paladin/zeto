package util

import (
	"math/big"

	"github.com/hyperledger-labs/zeto/go-sdk/internal/util"
	"github.com/iden3/go-rapidsnark/types"
)

func EncodeToBytes_Anon(proof *types.ProofData) ([]byte, error) {
	return util.EncodeToBytes_Anon(proof)
}

func EncodeToBytes_Enc(encryptionNonce *big.Int, ecdhPublicKey [2]*big.Int, encryptedValues []*big.Int, proof *types.ProofData) ([]byte, error) {
	return util.EncodeToBytes_Enc(encryptionNonce, ecdhPublicKey, encryptedValues, proof)
}

func EncodeToBytes_Nullifier(root *big.Int, proof *types.ProofData) ([]byte, error) {
	return util.EncodeToBytes_Nullifier(root, proof)
}

func EncodeToBytes_EncNullifier(root *big.Int, encryptionNonce *big.Int, ecdhPublicKey [2]*big.Int, encryptedValues []*big.Int, proof *types.ProofData) ([]byte, error) {
	return util.EncodeToBytes_EncNullifier(root, encryptionNonce, ecdhPublicKey, encryptedValues, proof)
}

func EncodeToBytes_EncNullifierNonRepudiation(root *big.Int, encryptionNonce *big.Int, ecdhPublicKey [2]*big.Int, encryptedValuesForReceiver, encryptedValuesForAuthority []*big.Int, proof *types.ProofData) ([]byte, error) {
	return util.EncodeToBytes_EncNullifierNonRepudiation(root, encryptionNonce, ecdhPublicKey, encryptedValuesForReceiver, encryptedValuesForAuthority, proof)
}

func EncodeToBytes_Qurrency(root *big.Int, encryptionNonce *big.Int, encryptedValues []*big.Int, encapsulatedSharedSecret [25]*big.Int, proof *types.ProofData) ([]byte, error) {
	return util.EncodeToBytes_Qurrency(root, encryptionNonce, encryptedValues, encapsulatedSharedSecret, proof)
}
