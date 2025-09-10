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
	"time"

	"github.com/hyperledger-labs/zeto/go-sdk/integration-test/common"
	"github.com/hyperledger-labs/zeto/go-sdk/internal/testutils"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/crypto"
	"github.com/iden3/go-rapidsnark/prover"
	"github.com/stretchr/testify/assert"
)

func (s *E2ETestSuite) TestZeto_anon_enc_nullifier_SuccessfulProving() {
	// s.T().Skip()
	calc, provingKey, err := common.LoadCircuit("anon_enc_nullifier")
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), calc)

	encryptionNonce := crypto.NewEncryptionNonce()
	ephemeralKeypair := testutils.NewKeypair()

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
		"encryptionNonce":       encryptionNonce,
		"ecdhPrivateKey":        ephemeralKeypair.PrivateKey.Scalar().BigInt(),
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
	assert.Equal(s.T(), 18, len(proof.PubSignals))
}
