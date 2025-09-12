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

// EncodeProofToBytes encodes the ZKProof to bytes for contract interaction
func EncodeToBytes_Anon(proof *types.ProofData) ([]byte, error) {
	proofStruct, err := convertProof(proof)
	if err != nil {
		return nil, err
	}

	// Create the ABI type with explicit components using shared function
	proofType := createProofType()

	// Use abi.Arguments to pack the data
	arguments := abi.Arguments{abi.Argument{Type: proofType}}
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

	// Create ABI types for each parameter using shared functions
	rootType := createUint256Type()
	proofType := createProofType()

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

func EncodeToBytes_Enc(encryptionNonce *big.Int, ecdhPublicKey [2]*big.Int, encryptedValues []*big.Int, proof *types.ProofData) ([]byte, error) {
	proofStruct, err := convertProof(proof)
	if err != nil {
		return nil, err
	}

	// Create ABI types for each parameter using shared functions
	encryptionNonceType := createUint256Type()
	ecdhPublicKeyType := createUint256Array2Type()
	encryptedValuesType := createUint256ArrayType()
	proofType := createProofType()

	// Pack the data using ABI encoding (matching TypeScript parameter order)
	arguments := abi.Arguments{
		abi.Argument{Type: encryptionNonceType},
		abi.Argument{Type: ecdhPublicKeyType},
		abi.Argument{Type: encryptedValuesType},
		abi.Argument{Type: proofType},
	}

	proofBytes, err := arguments.Pack(encryptionNonce, ecdhPublicKey, encryptedValues, proofStruct)
	if err != nil {
		return nil, err
	}

	return proofBytes, nil
}

func EncodeToBytes_EncNullifier(root, encryptionNonce *big.Int, ecdhPublicKey [2]*big.Int, encryptedValues []*big.Int, proof *types.ProofData) ([]byte, error) {
	proofStruct, err := convertProof(proof)
	if err != nil {
		return nil, err
	}

	// Create ABI types for each parameter using shared functions
	rootType := createUint256Type()
	encryptionNonceType := createUint256Type()
	ecdhPublicKeyType := createUint256Array2Type()
	encryptedValuesType := createUint256ArrayType()
	proofType := createProofType()

	// Pack the data using ABI encoding (matching TypeScript parameter order)
	arguments := abi.Arguments{
		abi.Argument{Type: rootType},
		abi.Argument{Type: encryptionNonceType},
		abi.Argument{Type: ecdhPublicKeyType},
		abi.Argument{Type: encryptedValuesType},
		abi.Argument{Type: proofType},
	}

	proofBytes, err := arguments.Pack(root, encryptionNonce, ecdhPublicKey, encryptedValues, proofStruct)
	if err != nil {
		return nil, err
	}

	return proofBytes, nil
}

func EncodeToBytes_EncNullifierNonRepudiation(root, encryptionNonce *big.Int, ecdhPublicKey [2]*big.Int, encryptedValuesForReceiver, encryptedValuesForAuthority []*big.Int, proof *types.ProofData) ([]byte, error) {
	proofStruct, err := convertProof(proof)
	if err != nil {
		return nil, err
	}

	// Create ABI types for each parameter using shared functions
	rootType := createUint256Type()
	encryptionNonceType := createUint256Type()
	ecdhPublicKeyType := createUint256Array2Type()
	encryptedValuesForReceiverType := createUint256ArrayType()
	encryptedValuesForAuthorityType := createUint256ArrayType()
	proofType := createProofType()

	// Pack the data using ABI encoding (matching TypeScript parameter order)
	arguments := abi.Arguments{
		abi.Argument{Type: rootType},
		abi.Argument{Type: encryptionNonceType},
		abi.Argument{Type: ecdhPublicKeyType},
		abi.Argument{Type: encryptedValuesForReceiverType},
		abi.Argument{Type: encryptedValuesForAuthorityType},
		abi.Argument{Type: proofType},
	}

	proofBytes, err := arguments.Pack(root, encryptionNonce, ecdhPublicKey, encryptedValuesForReceiver, encryptedValuesForAuthority, proofStruct)
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

	// Create ABI types for each parameter using shared functions
	rootType := createUint256Type()
	encryptionNonceType := createUint256Type()
	encryptedValuesType := createUint256ArrayType()
	encapsulatedSharedSecretType := createUint256Array25Type()
	proofType := createProofType()

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

// createProofType creates the common proof ABI type used across all encoding methods
func createProofType() abi.Type {
	t, _ := abi.NewType("tuple", "", []abi.ArgumentMarshaling{
		{Name: "pA", Type: "uint256[2]"},
		{Name: "pB", Type: "uint256[2][2]"},
		{Name: "pC", Type: "uint256[2]"},
	})
	return t
}

// createUint256Type creates the common uint256 ABI type
func createUint256Type() abi.Type {
	t, _ := abi.NewType("uint256", "", nil)
	return t
}

// createUint256ArrayType creates the common uint256[] ABI type
func createUint256ArrayType() abi.Type {
	t, _ := abi.NewType("uint256[]", "", nil)
	return t
}

// createUint256Array2Type creates the common uint256[2] ABI type
func createUint256Array2Type() abi.Type {
	t, _ := abi.NewType("uint256[2]", "", nil)
	return t
}

// createUint256Array25Type creates the common uint256[25] ABI type
func createUint256Array25Type() abi.Type {
	t, _ := abi.NewType("uint256[25]", "", nil)
	return t
}
