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

	"github.com/hyperledger-labs/zeto/go-sdk/integration-test/common"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/crypto"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-rapidsnark/prover"
	"github.com/stretchr/testify/assert"
)

func (s *E2ETestSuite) TestZeto_anon_SuccessfulProving() {
	// s.T().Skip()
	calc, provingKey, _, err := common.LoadCircuit("anon")
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), calc)

	witnessInputs := map[string]interface{}{
		"inputCommitments":      s.regularTest.InputCommitments,
		"inputValues":           s.regularTest.InputValues,
		"inputSalts":            s.regularTest.InputSalts,
		"inputOwnerPrivateKey":  s.sender.PrivateKeyBigInt,
		"outputCommitments":     s.regularTest.OutputCommitments,
		"outputValues":          s.regularTest.OutputValues,
		"outputSalts":           s.regularTest.OutputSalts,
		"outputOwnerPublicKeys": s.regularTest.OutputOwnerPublicKeys,
	}

	// calculate the witness object for checking correctness
	witness, err := calc.CalculateWitness(witnessInputs, true)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), witness)

	assert.Equal(s.T(), 0, witness[0].Cmp(big.NewInt(1)))
	assert.Equal(s.T(), 0, witness[1].Cmp(s.regularTest.InputCommitments[0]))
	assert.Equal(s.T(), 0, witness[2].Cmp(s.regularTest.InputCommitments[1]))
	assert.Equal(s.T(), 0, witness[3].Cmp(s.regularTest.OutputCommitments[0]))
	assert.Equal(s.T(), 0, witness[4].Cmp(s.regularTest.OutputCommitments[1]))

	// generate the witness binary to feed into the prover
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
	assert.Equal(s.T(), 4, len(proof.PubSignals))
}

func (s *E2ETestSuite) TestZeto_anon_batch_SuccessfulProving() {
	// s.T().Skip()
	calc, provingKey, _, err := common.LoadCircuit("anon_batch")
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), calc)

	witnessInputs := map[string]interface{}{
		"inputCommitments":      s.batchTest.InputCommitments,
		"inputValues":           s.batchTest.InputValues,
		"inputSalts":            s.batchTest.InputSalts,
		"inputOwnerPrivateKey":  s.sender.PrivateKeyBigInt,
		"outputCommitments":     s.batchTest.OutputCommitments,
		"outputValues":          s.batchTest.OutputValues,
		"outputSalts":           s.batchTest.OutputSalts,
		"outputOwnerPublicKeys": s.batchTest.OutputOwnerPublicKeys,
	}

	// generate the witness binary to feed into the prover
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
	assert.Equal(s.T(), 20, len(proof.PubSignals))
}

func (s *E2ETestSuite) TestZeto_anon_burn_SuccessfulProving() {
	// s.T().Skip()
	calc, provingKey, _, err := common.LoadCircuit("burn")
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), calc)

	// burn 55 out of 70 with the two input values, and output 15
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
		"inputCommitments": s.regularTest.InputCommitments,
		"inputValues":      s.regularTest.InputValues,
		"inputSalts":       s.regularTest.InputSalts,
		"ownerPrivateKey":  s.sender.PrivateKeyBigInt,
		"outputCommitment": outputCommitments,
		"outputValue":      outputValues,
		"outputSalt":       outputSalts,
	}

	// generate the witness binary to feed into the prover
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
	assert.Equal(s.T(), 3, len(proof.PubSignals))
}
