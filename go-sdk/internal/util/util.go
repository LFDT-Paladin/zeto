package util

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/iden3/go-rapidsnark/types"
)

type EncodedProof struct {
	PA [2]string    `json:"pA"`
	PB [2][2]string `json:"pB"`
	PC [2]string    `json:"pC"`
}

// EncodeProofToBytes encodes the ZKProof to bytes for contract interaction
func EncodeToBytes_Anon(proof *types.ProofData) ([]byte, error) {
	proofStruct, err := convertProof(proof)
	if err != nil {
		return nil, err
	}
	jsonObj := map[string]interface{}{
		"proof": proofStruct,
	}
	proofJSONBytes, _ := json.Marshal(jsonObj)

	// Create the ABI type with explicit components using shared function
	proofType := createProofType()

	// Use abi.Arguments to pack the data
	arguments := abi.ParameterArray{proofType}
	proofBytes, err := arguments.EncodeABIDataJSON(proofJSONBytes)
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
	jsonObj := map[string]interface{}{
		"root":  "0x" + root.Text(16),
		"proof": proofStruct,
	}
	proofJSONBytes, _ := json.Marshal(jsonObj)

	// Create ABI types for each parameter using shared functions
	rootType := createUint256Type("root")
	proofType := createProofType()

	// Pack the data using ABI encoding (matching TypeScript parameter order)
	arguments := abi.ParameterArray{rootType, proofType}

	proofBytes, err := arguments.EncodeABIDataJSON(proofJSONBytes)
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
	jsonObj := map[string]interface{}{
		"encryptionNonce": "0x" + encryptionNonce.Text(16),
		"ecdhPublicKey":   [2]string{"0x" + ecdhPublicKey[0].Text(16), "0x" + ecdhPublicKey[1].Text(16)},
		"encryptedValues": func() []string {
			values := make([]string, len(encryptedValues))
			for i, v := range encryptedValues {
				values[i] = "0x" + v.Text(16)
			}
			return values
		}(),
		"proof": proofStruct,
	}
	proofJSONBytes, _ := json.Marshal(jsonObj)

	// Create ABI types for each parameter using shared functions
	encryptionNonceType := createUint256Type("encryptionNonce")
	ecdhPublicKeyType := createUint256Array2Type("ecdhPublicKey")
	encryptedValuesType := createUint256ArrayType("encryptedValues")
	proofType := createProofType()

	// Pack the data using ABI encoding (matching TypeScript parameter order)
	arguments := abi.ParameterArray{
		encryptionNonceType,
		ecdhPublicKeyType,
		encryptedValuesType,
		proofType,
	}

	proofBytes, err := arguments.EncodeABIDataJSON(proofJSONBytes)
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
	jsonObj := map[string]interface{}{
		"root":            "0x" + root.Text(16),
		"encryptionNonce": "0x" + encryptionNonce.Text(16),
		"ecdhPublicKey":   [2]string{"0x" + ecdhPublicKey[0].Text(16), "0x" + ecdhPublicKey[1].Text(16)},
		"encryptedValues": func() []string {
			values := make([]string, len(encryptedValues))
			for i, v := range encryptedValues {
				values[i] = "0x" + v.Text(16)
			}
			return values
		}(),
		"proof": proofStruct,
	}
	proofJSONBytes, _ := json.Marshal(jsonObj)

	// Create ABI types for each parameter using shared functions
	rootType := createUint256Type("root")
	encryptionNonceType := createUint256Type("encryptionNonce")
	ecdhPublicKeyType := createUint256Array2Type("ecdhPublicKey")
	encryptedValuesType := createUint256ArrayType("encryptedValues")
	proofType := createProofType()

	// Pack the data using ABI encoding (matching TypeScript parameter order)
	arguments := abi.ParameterArray{
		rootType,
		encryptionNonceType,
		ecdhPublicKeyType,
		encryptedValuesType,
		proofType,
	}

	proofBytes, err := arguments.EncodeABIDataJSON(proofJSONBytes)
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
	jsonObj := map[string]interface{}{
		"root":            "0x" + root.Text(16),
		"encryptionNonce": "0x" + encryptionNonce.Text(16),
		"ecdhPublicKey":   [2]string{"0x" + ecdhPublicKey[0].Text(16), "0x" + ecdhPublicKey[1].Text(16)},
		"encryptedValuesForReceiver": func() []string {
			values := make([]string, len(encryptedValuesForReceiver))
			for i, v := range encryptedValuesForReceiver {
				values[i] = "0x" + v.Text(16)
			}
			return values
		}(),
		"encryptedValuesForAuthority": func() []string {
			values := make([]string, len(encryptedValuesForAuthority))
			for i, v := range encryptedValuesForAuthority {
				values[i] = "0x" + v.Text(16)
			}
			return values
		}(),
		"proof": proofStruct,
	}
	proofJSONBytes, _ := json.Marshal(jsonObj)

	// Create ABI types for each parameter using shared functions
	rootType := createUint256Type("root")
	encryptionNonceType := createUint256Type("encryptionNonce")
	ecdhPublicKeyType := createUint256Array2Type("ecdhPublicKey")
	encryptedValuesForReceiverType := createUint256ArrayType("encryptedValuesForReceiver")
	encryptedValuesForAuthorityType := createUint256ArrayType("encryptedValuesForAuthority")
	proofType := createProofType()

	// Pack the data using ABI encoding (matching TypeScript parameter order)
	arguments := abi.ParameterArray{
		rootType,
		encryptionNonceType,
		ecdhPublicKeyType,
		encryptedValuesForReceiverType,
		encryptedValuesForAuthorityType,
		proofType,
	}

	proofBytes, err := arguments.EncodeABIDataJSON(proofJSONBytes)
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
	jsonObj := map[string]interface{}{
		"root":            "0x" + root.Text(16),
		"encryptionNonce": "0x" + encryptionNonce.Text(16),
		"encryptedValues": func() []string {
			values := make([]string, len(encryptedValues))
			for i, v := range encryptedValues {
				values[i] = "0x" + v.Text(16)
			}
			return values
		}(),
		"encapsulatedSharedSecret": func() []string {
			values := make([]string, len(encapsulatedSharedSecret))
			for i, v := range encapsulatedSharedSecret {
				values[i] = "0x" + v.Text(16)
			}
			return values
		}(),
		"proof": proofStruct,
	}
	proofJSONBytes, _ := json.Marshal(jsonObj)

	// Create ABI types for each parameter using shared functions
	rootType := createUint256Type("root")
	encryptionNonceType := createUint256Type("encryptionNonce")
	encryptedValuesType := createUint256ArrayType("encryptedValues")
	encapsulatedSharedSecretType := createUint256Array25Type("encapsulatedSharedSecret")
	proofType := createProofType()

	// Pack the data using ABI encoding (matching TypeScript parameter order)
	arguments := abi.ParameterArray{
		rootType,
		encryptionNonceType,
		encryptedValuesType,
		encapsulatedSharedSecretType,
		proofType,
	}

	proofBytes, err := arguments.EncodeABIDataJSON(proofJSONBytes)
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
		PA: [2]string{"0x" + pA[0].Text(16), "0x" + pA[1].Text(16)},
		PB: [2][2]string{
			// note that the order of the elements in the pB array is reversed in the contract
			{"0x" + pB[0][1].Text(16), "0x" + pB[0][0].Text(16)},
			{"0x" + pB[1][1].Text(16), "0x" + pB[1][0].Text(16)},
		},
		PC: [2]string{"0x" + pC[0].Text(16), "0x" + pC[1].Text(16)},
	}

	return &proofStruct, nil
}

// createProofType creates the common proof ABI type used across all encoding methods
func createProofType() *abi.Parameter {
	t := &abi.Parameter{
		Type: "tuple",
		Name: "proof",
		Components: abi.ParameterArray{
			{Name: "pA", Type: "uint256[2]"},
			{Name: "pB", Type: "uint256[2][2]"},
			{Name: "pC", Type: "uint256[2]"},
		},
	}
	return t
}

// createUint256Type creates the common uint256 ABI type
func createUint256Type(name string) *abi.Parameter {
	t := &abi.Parameter{
		Type: "uint256",
		Name: name,
	}
	return t
}

// createUint256ArrayType creates the common uint256[] ABI type
func createUint256ArrayType(name string) *abi.Parameter {
	t := &abi.Parameter{
		Type: "uint256[]",
		Name: name,
	}
	return t
}

// createUint256Array2Type creates the common uint256[2] ABI type
func createUint256Array2Type(name string) *abi.Parameter {
	t := &abi.Parameter{
		Type: "uint256[2]",
		Name: name,
	}
	return t
}

// createUint256Array25Type creates the common uint256[25] ABI type
func createUint256Array25Type(name string) *abi.Parameter {
	t := &abi.Parameter{
		Type: "uint256[25]",
		Name: name,
	}
	return t
}
