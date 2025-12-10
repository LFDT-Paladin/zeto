package common

import (
	"math/big"
	"testing"

	"github.com/hyperledger-labs/zeto/go-sdk/internal/crypto/hash"
	"github.com/hyperledger-labs/zeto/go-sdk/internal/sparse-merkle-tree/smt"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/sparse-merkle-tree/core"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/sparse-merkle-tree/node"
	"github.com/stretchr/testify/assert"
)

const MAX_HEIGHT = 64

func BuildMerkleProofs(inputCommitments []*big.Int, db core.Storage, t *testing.T) ([][]*big.Int, []*big.Int, *big.Int) {
	mt, err := smt.NewMerkleTree(db, MAX_HEIGHT)
	assert.NoError(t, err)

	root := mt.Root().BigInt()

	proofs, _, err := mt.GenerateProofs(inputCommitments, nil)
	assert.NoError(t, err)

	smtProofs := make([][]*big.Int, len(proofs))
	enabled := make([]*big.Int, len(proofs))
	for i, proof := range proofs {
		circomProof, err := proof.ToCircomVerifierProof(inputCommitments[i], inputCommitments[i], mt.Root(), MAX_HEIGHT)
		assert.NoError(t, err)
		proofSiblings := make([]*big.Int, len(circomProof.Siblings)-1)
		for i, s := range circomProof.Siblings[0 : len(circomProof.Siblings)-1] {
			proofSiblings[i] = s.BigInt()
		}
		smtProofs[i] = proofSiblings
		enabled[i] = big.NewInt(1)
	}

	return smtProofs, enabled, root
}

func AddCommitmentToMerkleTree(mt core.SparseMerkleTree, commitment *big.Int, t *testing.T) {
	idx, _ := node.NewNodeIndexFromBigInt(commitment, &hash.PoseidonHasher{})
	utxo := node.NewIndexOnly(idx)
	n, err := node.NewLeafNode(utxo, nil)
	assert.NoError(t, err)
	err = mt.AddLeaf(n)
	assert.NoError(t, err)
}
