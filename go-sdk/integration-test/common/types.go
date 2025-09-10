package common

import (
	"math/big"
	"testing"

	"github.com/hyperledger-labs/zeto/go-sdk/internal/testutils"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/crypto"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/sparse-merkle-tree/core"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

type Signals struct {
	InputValues           []*big.Int
	InputSalts            []*big.Int
	InputCommitments      []*big.Int
	Nullifiers            []*big.Int
	OutputValues          []*big.Int
	OutputSalts           []*big.Int
	OutputCommitments     []*big.Int
	OutputOwnerPublicKeys [][]*big.Int
	MerkleProofs          [][]*big.Int
	Enabled               []*big.Int
	Root                  *big.Int
}

func NewSignals(sender, receiver *testutils.User, isBatch bool, db core.Storage, t *testing.T) *Signals {
	s := &Signals{
		InputValues:  []*big.Int{big.NewInt(10), big.NewInt(20)},
		OutputValues: []*big.Int{big.NewInt(15), big.NewInt(15)},
	}
	if isBatch {
		s = &Signals{
			InputValues:  []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4), big.NewInt(5), big.NewInt(6), big.NewInt(7), big.NewInt(8), big.NewInt(9), big.NewInt(10)},
			OutputValues: []*big.Int{big.NewInt(10), big.NewInt(9), big.NewInt(8), big.NewInt(7), big.NewInt(6), big.NewInt(5), big.NewInt(4), big.NewInt(3), big.NewInt(2), big.NewInt(1)},
		}
	}
	size := len(s.InputValues)

	s.InputCommitments = make([]*big.Int, 0, size)
	s.InputSalts = make([]*big.Int, 0, size)
	for _, value := range s.InputValues {
		salt := crypto.NewSalt()
		commitment, _ := poseidon.Hash([]*big.Int{value, salt, sender.PublicKey.X, sender.PublicKey.Y})
		s.InputCommitments = append(s.InputCommitments, commitment)
		s.InputSalts = append(s.InputSalts, salt)
	}

	s.Nullifiers = make([]*big.Int, 0, size)
	for j, value := range s.InputValues {
		salt := s.InputSalts[j]
		nullifier, _ := poseidon.Hash([]*big.Int{value, salt, sender.PrivateKeyBigInt})
		s.Nullifiers = append(s.Nullifiers, nullifier)
	}

	if db != nil {
		s.MerkleProofs, s.Enabled, s.Root = BuildMerkleProofs(s.InputCommitments, db, t)
	}

	s.OutputCommitments = make([]*big.Int, 0, size)
	s.OutputSalts = make([]*big.Int, 0, size)
	for _, value := range s.OutputValues {
		salt := crypto.NewSalt()
		commitment, _ := poseidon.Hash([]*big.Int{value, salt, receiver.PublicKey.X, receiver.PublicKey.Y})
		s.OutputCommitments = append(s.OutputCommitments, commitment)
		s.OutputSalts = append(s.OutputSalts, salt)
	}

	s.OutputOwnerPublicKeys = make([][]*big.Int, 0, size)
	for range size {
		s.OutputOwnerPublicKeys = append(s.OutputOwnerPublicKeys, []*big.Int{receiver.PublicKey.X, receiver.PublicKey.Y})
	}

	return s
}
