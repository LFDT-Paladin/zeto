package eth_e2e

import (
	"crypto/rand"
	"math/big"
	"time"

	"github.com/hyperledger-labs/zeto/go-sdk/integration-test/common"
	"github.com/hyperledger-labs/zeto/go-sdk/internal/util"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/crypto"
	"github.com/iden3/go-rapidsnark/prover"
	"github.com/stretchr/testify/assert"
)

func (s *EthE2ETestSuite) generateProof_anon(signals *common.Signals) []byte {
	calc, provingKey, _, err := common.LoadCircuit("anon")
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), calc)

	witnessInputs := map[string]interface{}{
		"inputCommitments":      signals.InputCommitments,
		"inputValues":           signals.InputValues,
		"inputSalts":            signals.InputSalts,
		"inputOwnerPrivateKey":  s.sender.PrivateKeyBigInt,
		"outputCommitments":     signals.OutputCommitments,
		"outputValues":          signals.OutputValues,
		"outputSalts":           signals.OutputSalts,
		"outputOwnerPublicKeys": signals.OutputOwnerPublicKeys,
	}

	// generate the witness binary to feed into the prover
	startTime := time.Now()
	witnessBin, err := calc.CalculateWTNSBin(witnessInputs, true)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), witnessBin)

	proof, err := prover.Groth16Prover(provingKey, witnessBin)
	elapsedTime := time.Since(startTime)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), proof)
	s.T().Logf("Proving time: %s\n", elapsedTime)
	s.provingTimes = append(s.provingTimes, elapsedTime)

	encodedProof, err := util.EncodeToBytes_Anon(proof.Proof)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), encodedProof)

	return encodedProof
}

func (s *EthE2ETestSuite) generateProof_anon_qurrency(signals *common.Signals) []byte {
	calc, provingKey, _, err := common.LoadCircuit("anon_nullifier_qurrency_transfer")
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), calc)

	nonce := crypto.NewEncryptionNonce()
	randomBytes := make([]byte, 32)
	n, _ := rand.Read(randomBytes)
	assert.Equal(s.T(), 32, n, "Expected to read 32 random bytes")
	// convert the randomBytes into a little-endian bit array
	bitArray := crypto.BytesToBits(randomBytes)
	// convert the bit array into a big.Int array
	randomBits := make([]*big.Int, len(bitArray))
	for i, bit := range bitArray {
		randomBits[i] = big.NewInt(int64(bit))
	}

	witnessInputs := map[string]interface{}{
		"nullifiers":            signals.Nullifiers,
		"inputCommitments":      signals.InputCommitments,
		"inputValues":           signals.InputValues,
		"inputSalts":            signals.InputSalts,
		"inputOwnerPrivateKey":  s.sender.PrivateKeyBigInt,
		"root":                  signals.Root,
		"merkleProof":           signals.MerkleProofs,
		"enabled":               signals.Enabled,
		"outputCommitments":     signals.OutputCommitments,
		"outputValues":          signals.OutputValues,
		"outputSalts":           signals.OutputSalts,
		"outputOwnerPublicKeys": signals.OutputOwnerPublicKeys,
		"encryptionNonce":       nonce,
		"randomness":            randomBits,
	}

	startTime := time.Now()
	witnessBin, err := calc.CalculateWTNSBin(witnessInputs, true)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), witnessBin)

	proof, err := prover.Groth16Prover(provingKey, witnessBin)
	elapsedTime := time.Since(startTime)
	s.T().Logf("Proving time: %s\n", elapsedTime)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), 3, len(proof.Proof.A))
	assert.Equal(s.T(), 3, len(proof.Proof.B))
	assert.Equal(s.T(), 3, len(proof.Proof.C))
	assert.Equal(s.T(), 48, len(proof.PubSignals))
	s.provingTimes = append(s.provingTimes, elapsedTime)

	encapsulatedSharedSecret, encryptedValues := common.ExtractSharedSecretAndEncryptedValues(s.T(), proof)

	encodedProof, err := util.EncodeToBytes_Qurrency(signals.Root, nonce, encryptedValues, encapsulatedSharedSecret, proof.Proof)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), encodedProof)

	return encodedProof
}
