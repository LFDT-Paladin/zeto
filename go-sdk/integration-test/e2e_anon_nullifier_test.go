// Copyright © 2025 Kaleido, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package integration_test

import (
	"fmt"
	"math/big"
	"time"

	"github.com/LFDT-Paladin/smt/pkg/crypto"
	"github.com/LFDT-Paladin/zeto/go-sdk/integration-test/common"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-rapidsnark/prover"
	"github.com/stretchr/testify/assert"
)

func (s *E2ETestSuite) TestZeto_anon_nullifier_SuccessfulProving() {
	// s.T().Skip()
	calc, provingKey, _, err := common.LoadCircuit("anon_nullifier_transfer")
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), calc)

	witnessInputs := map[string]interface{}{
		"nullifiers":            s.regularTest.Nullifiers,
		"inputCommitments":      s.regularTest.InputCommitments,
		"inputValues":           s.regularTest.InputValues,
		"inputSalts":            s.regularTest.InputSalts,
		"inputOwnerPrivateKey":  s.sender.PrivateKeyBigInt,
		"root":                  s.regularTest.Root,
		"merkleProof":           s.regularTest.MerkleProofs,
		"enabled":               s.regularTest.Enabled,
		"outputCommitments":     s.regularTest.OutputCommitments,
		"outputValues":          s.regularTest.OutputValues,
		"outputSalts":           s.regularTest.OutputSalts,
		"outputOwnerPublicKeys": s.regularTest.OutputOwnerPublicKeys,
	}

	startTime := time.Now()
	witnessBin, err := calc.CalculateWTNSBin(witnessInputs, true)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), witnessBin)

	proof, err := prover.Groth16Prover(provingKey, witnessBin)
	elapsedTime := time.Since(startTime)
	fmt.Printf("Proving time: %s\n", elapsedTime)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), 3, len(proof.Proof.A))
	assert.Equal(s.T(), 3, len(proof.Proof.B))
	assert.Equal(s.T(), 3, len(proof.Proof.C))
	assert.Equal(s.T(), 7, len(proof.PubSignals))
}

// The locked-input transfer flow no longer has its own dedicated circuit:
// under the new {ILockableCapability} architecture, locked UTXOs live in a
// flat per-lock mapping (no SMT, no nullifiers), so settling a lock now
// verifies against the simpler `anon` circuit. Proving against `anon` is
// already covered by `e2e_anon_test.go` (TestZeto_anon_SuccessfulProving),
// so we no longer need a dedicated `_locked` integration test here.

func (s *E2ETestSuite) TestZeto_anon_nullifier_batch_SuccessfulProving() {
	// s.T().Skip()
	calc, provingKey, _, err := common.LoadCircuit("anon_nullifier_transfer_batch")
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), calc)

	witnessInputs := map[string]interface{}{
		"nullifiers":            s.batchTest.Nullifiers,
		"inputCommitments":      s.batchTest.InputCommitments,
		"inputValues":           s.batchTest.InputValues,
		"inputSalts":            s.batchTest.InputSalts,
		"inputOwnerPrivateKey":  s.sender.PrivateKeyBigInt,
		"root":                  s.batchTest.Root,
		"merkleProof":           s.batchTest.MerkleProofs,
		"enabled":               s.batchTest.Enabled,
		"outputCommitments":     s.batchTest.OutputCommitments,
		"outputValues":          s.batchTest.OutputValues,
		"outputSalts":           s.batchTest.OutputSalts,
		"outputOwnerPublicKeys": s.batchTest.OutputOwnerPublicKeys,
	}

	startTime := time.Now()
	witnessBin, err := calc.CalculateWTNSBin(witnessInputs, true)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), witnessBin)

	proof, err := prover.Groth16Prover(provingKey, witnessBin)
	elapsedTime := time.Since(startTime)
	fmt.Printf("Proving time: %s\n", elapsedTime)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), 3, len(proof.Proof.A))
	assert.Equal(s.T(), 3, len(proof.Proof.B))
	assert.Equal(s.T(), 3, len(proof.Proof.C))
	assert.Equal(s.T(), 31, len(proof.PubSignals))
}

func (s *E2ETestSuite) TestZeto_anon_nullifier_burn_SuccessfulProving() {
	// s.T().Skip()
	calc, provingKey, _, err := common.LoadCircuit("burn_nullifier")
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), calc)

	// burn 55 out of 70, and return 15
	outputValues := []*big.Int{big.NewInt(15)}

	outputCommitments := make([]*big.Int, 0, 1)
	outputSalts := make([]*big.Int, 0, 1)
	for _, value := range outputValues {
		salt := crypto.NewSalt()
		commitment, _ := poseidon.Hash([]*big.Int{value, salt, s.sender.PublicKey.X, s.sender.PublicKey.Y})
		outputCommitments = append(outputCommitments, commitment)
		outputSalts = append(outputSalts, salt)
	}

	witnessInputs := map[string]interface{}{
		"nullifiers":       s.regularTest.Nullifiers,
		"inputCommitments": s.regularTest.InputCommitments,
		"inputValues":      s.regularTest.InputValues,
		"inputSalts":       s.regularTest.InputSalts,
		"ownerPrivateKey":  s.sender.PrivateKeyBigInt,
		"root":             s.regularTest.Root,
		"merkleProof":      s.regularTest.MerkleProofs,
		"enabled":          s.regularTest.Enabled,
		"outputCommitment": outputCommitments,
		"outputValue":      outputValues,
		"outputSalt":       outputSalts,
	}

	startTime := time.Now()
	witnessBin, err := calc.CalculateWTNSBin(witnessInputs, true)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), witnessBin)

	proof, err := prover.Groth16Prover(provingKey, witnessBin)
	elapsedTime := time.Since(startTime)
	fmt.Printf("Proving time: %s\n", elapsedTime)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), 3, len(proof.Proof.A))
	assert.Equal(s.T(), 3, len(proof.Proof.B))
	assert.Equal(s.T(), 3, len(proof.Proof.C))
	assert.Equal(s.T(), 6, len(proof.PubSignals))
}
