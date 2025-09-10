package util

import (
	"github.com/hyperledger-labs/zeto/go-sdk/internal/util"
	"github.com/iden3/go-rapidsnark/types"
)

func EncodeProofToBytes(proof *types.ZKProof) ([]byte, error) {
	return util.EncodeProofToBytes(proof)
}
