package util

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	zktypes "github.com/iden3/go-rapidsnark/types"
)

// EncodeProofToBytes encodes the ZKProof to bytes for contract interaction
func EncodeProofToBytes(proof *zktypes.ZKProof) ([]byte, error) {
	if proof == nil || proof.Proof == nil {
		return nil, fmt.Errorf("proof cannot be nil")
	}

	// Convert A (pA) from []string to [2]*big.Int
	pA := make([]*big.Int, 2)
	for i := range 2 {
		val := proof.Proof.A[i]
		pA[i], _ = new(big.Int).SetString(val, 10)
	}

	// Convert B (pB) from [][]string to [2][2]*big.Int
	pB := make([][]*big.Int, 2)
	for i := range 2 {
		pB[i] = make([]*big.Int, 2)
		for j := range 2 {
			val := proof.Proof.B[i][j]
			pB[i][j], _ = new(big.Int).SetString(val, 10)
		}
	}

	// Convert C (pC) from []string to [2]*big.Int
	pC := make([]*big.Int, 2)
	for i := range 2 {
		val := proof.Proof.C[i]
		pC[i], _ = new(big.Int).SetString(val, 10)
	}

	// Use the simple AbiCoder approach - encode based on signature
	// This is equivalent to: new AbiCoder().encode(["tuple(uint256[2] pA, uint256[2][2] pB, uint256[2] pC)"], [proof])

	// Create the ABI type with explicit components
	args, err := abi.NewType("tuple", "", []abi.ArgumentMarshaling{
		{Name: "pA", Type: "uint256[2]"},
		{Name: "pB", Type: "uint256[2][2]"},
		{Name: "pC", Type: "uint256[2]"},
	})
	if err != nil {
		return nil, err
	}

	// Create the proof struct for ABI encoding
	proofStruct := struct {
		PA [2]*big.Int    `abi:"pA"`
		PB [2][2]*big.Int `abi:"pB"`
		PC [2]*big.Int    `abi:"pC"`
	}{
		PA: [2]*big.Int{pA[0], pA[1]},
		PB: [2][2]*big.Int{
			// note that the order of the elements in the pB array is reversed in the contract
			{pB[0][1], pB[0][0]},
			{pB[1][1], pB[1][0]},
		},
		PC: [2]*big.Int{pC[0], pC[1]},
	}

	// Use abi.Arguments to pack the data
	arguments := abi.Arguments{abi.Argument{Type: args}}
	proofBytes, err := arguments.Pack(proofStruct)
	if err != nil {
		return nil, err
	}

	return proofBytes, nil
}
