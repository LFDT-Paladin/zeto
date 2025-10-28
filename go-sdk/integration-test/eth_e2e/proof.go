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
	witnessStartTime := time.Now()
	witnessBin, err := calc.CalculateWTNSBin(witnessInputs, true)
	witnessElapsedTime := time.Since(witnessStartTime)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), witnessBin)
	s.T().Logf("Witness generation time: %s\n", witnessElapsedTime)
	s.witnessTimes = append(s.witnessTimes, witnessElapsedTime)

	// generate the proof
	proofStartTime := time.Now()
	proof, err := prover.Groth16Prover(provingKey, witnessBin)
	proofElapsedTime := time.Since(proofStartTime)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), proof)
	s.T().Logf("Proving time: %s\n", proofElapsedTime)
	s.provingTimes = append(s.provingTimes, proofElapsedTime)

	encodedProof, err := util.EncodeToBytes_Anon(proof.Proof)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), encodedProof)

	return encodedProof
}

func (s *EthE2ETestSuite) generateProof_anon_nullifier(signals *common.Signals) []byte {
	calc, provingKey, _, err := common.LoadCircuit("anon_nullifier_transfer")
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), calc)

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
	}

	// generate the witness binary to feed into the prover
	witnessStartTime := time.Now()
	witnessBin, err := calc.CalculateWTNSBin(witnessInputs, true)
	witnessElapsedTime := time.Since(witnessStartTime)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), witnessBin)
	s.T().Logf("Witness generation time: %s\n", witnessElapsedTime)
	s.witnessTimes = append(s.witnessTimes, witnessElapsedTime)

	// generate the proof
	proofStartTime := time.Now()
	proof, err := prover.Groth16Prover(provingKey, witnessBin)
	proofElapsedTime := time.Since(proofStartTime)
	s.T().Logf("Proving time: %s\n", proofElapsedTime)
	assert.NoError(s.T(), err)
	s.provingTimes = append(s.provingTimes, proofElapsedTime)

	encodedProof, err := util.EncodeToBytes_Nullifier(signals.Root, proof.Proof)
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

	// generate the witness binary to feed into the prover
	witnessStartTime := time.Now()
	witnessBin, err := calc.CalculateWTNSBin(witnessInputs, true)
	witnessElapsedTime := time.Since(witnessStartTime)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), witnessBin)
	s.T().Logf("Witness generation time: %s\n", witnessElapsedTime)
	s.witnessTimes = append(s.witnessTimes, witnessElapsedTime)

	// generate the proof
	proofStartTime := time.Now()
	proof, err := prover.Groth16Prover(provingKey, witnessBin)
	proofElapsedTime := time.Since(proofStartTime)
	s.T().Logf("Proving time: %s\n", proofElapsedTime)
	assert.NoError(s.T(), err)
	s.provingTimes = append(s.provingTimes, proofElapsedTime)

	encapsulatedSharedSecret, encryptedValues := common.ExtractSharedSecretAndEncryptedValues(s.T(), proof)

	encodedProof, err := util.EncodeToBytes_Qurrency(signals.Root, nonce, encryptedValues, encapsulatedSharedSecret, proof.Proof)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), encodedProof)

	return encodedProof
}
