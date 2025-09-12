package util

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/iden3/go-rapidsnark/types"
)

type EncodedProof struct {
	PA [2]*big.Int    `abi:"pA"`
	PB [2][2]*big.Int `abi:"pB"`
	PC [2]*big.Int    `abi:"pC"`
}

type EncodedProof_Qurrency struct {
	Root                     *big.Int     `abi:"root"`
	EncryptionNonce          *big.Int     `abi:"encryptionNonce"`
	EncryptedValues          []*big.Int   `abi:"encryptedValues"`
	EncapsulatedSharedSecret []*big.Int   `abi:"encapsulatedSharedSecret"`
	Proof                    EncodedProof `abi:"proof"`
}

// EncodeProofToBytes encodes the ZKProof to bytes for contract interaction
func EncodeToBytes_Anon(proof *types.ProofData) ([]byte, error) {
	proofStruct, err := convertProof(proof)
	if err != nil {
		return nil, err
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

	// Use abi.Arguments to pack the data
	arguments := abi.Arguments{abi.Argument{Type: args}}
	proofBytes, err := arguments.Pack(proofStruct)
	if err != nil {
		return nil, err
	}

	return proofBytes, nil
}

func EncodeToBytes_Nullifier(root *big.Int, proof *types.ProofData) ([]byte, error) {
	proofStruct, err := convertProof(proof)
	if err != nil {
		return nil, err
	}

	// Create ABI types for each parameter (matching TypeScript AbiCoder.encode approach)
	rootType, err := abi.NewType("uint256", "", nil)
	if err != nil {
		return nil, err
	}

	proofType, err := abi.NewType("tuple", "", []abi.ArgumentMarshaling{
		{Name: "pA", Type: "uint256[2]"},
		{Name: "pB", Type: "uint256[2][2]"},
		{Name: "pC", Type: "uint256[2]"},
	})
	if err != nil {
		return nil, err
	}

	// Pack the data using ABI encoding (matching TypeScript parameter order)
	arguments := abi.Arguments{
		abi.Argument{Type: rootType},
		abi.Argument{Type: proofType},
	}

	proofBytes, err := arguments.Pack(root, proofStruct)
	if err != nil {
		return nil, err
	}

	return proofBytes, nil
}

func EncodeToBytes_Qurrency(root *big.Int, encryptionNonce *big.Int, encryptedValues []*big.Int, encapsulatedSharedSecret [25]*big.Int, proof *types.ProofData) ([]byte, error) {
	proofStruct, err := convertProof(proof)
	if err != nil {
		return nil, err
	}

	// Create ABI types for each parameter (matching TypeScript AbiCoder.encode approach)
	rootType, err := abi.NewType("uint256", "", nil)
	if err != nil {
		return nil, err
	}

	encryptionNonceType, err := abi.NewType("uint256", "", nil)
	if err != nil {
		return nil, err
	}

	encryptedValuesType, err := abi.NewType("uint256[]", "", nil)
	if err != nil {
		return nil, err
	}

	encapsulatedSharedSecretType, err := abi.NewType("uint256[25]", "", nil)
	if err != nil {
		return nil, err
	}

	proofType, err := abi.NewType("tuple", "", []abi.ArgumentMarshaling{
		{Name: "pA", Type: "uint256[2]"},
		{Name: "pB", Type: "uint256[2][2]"},
		{Name: "pC", Type: "uint256[2]"},
	})
	if err != nil {
		return nil, err
	}

	// Pack the data using ABI encoding (matching TypeScript parameter order)
	arguments := abi.Arguments{
		abi.Argument{Type: rootType},
		abi.Argument{Type: encryptionNonceType},
		abi.Argument{Type: encryptedValuesType},
		abi.Argument{Type: encapsulatedSharedSecretType},
		abi.Argument{Type: proofType},
	}

	proofBytes, err := arguments.Pack(root, encryptionNonce, encryptedValues, encapsulatedSharedSecret, proofStruct)
	if err != nil {
		return nil, err
	}

	return proofBytes, nil
}

func convertProof(proof *types.ProofData) (*EncodedProof, error) {
	if proof == nil {
		return nil, fmt.Errorf("proof cannot be nil")
	}

	// Convert A (pA) from []string to [2]*big.Int
	pA := make([]*big.Int, 2)
	for i := range 2 {
		val := proof.A[i]
		pA[i], _ = new(big.Int).SetString(val, 10)
	}

	// Convert B (pB) from [][]string to [2][2]*big.Int
	pB := make([][]*big.Int, 2)
	for i := range 2 {
		pB[i] = make([]*big.Int, 2)
		for j := range 2 {
			val := proof.B[i][j]
			pB[i][j], _ = new(big.Int).SetString(val, 10)
		}
	}

	// Convert C (pC) from []string to [2]*big.Int
	pC := make([]*big.Int, 2)
	for i := range 2 {
		val := proof.C[i]
		pC[i], _ = new(big.Int).SetString(val, 10)
	}

	// Create the proof struct for ABI encoding (matching TypeScript encodeProof output)
	proofStruct := EncodedProof{
		PA: [2]*big.Int{pA[0], pA[1]},
		PB: [2][2]*big.Int{
			// note that the order of the elements in the pB array is reversed in the contract
			{pB[0][1], pB[0][0]},
			{pB[1][1], pB[1][0]},
		},
		PC: [2]*big.Int{pC[0], pC[1]},
	}

	return &proofStruct, nil
}
