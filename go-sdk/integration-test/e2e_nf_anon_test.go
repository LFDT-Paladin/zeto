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
	"github.com/hyperledger-labs/zeto/go-sdk/internal/testutils"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/crypto"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/utxo"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-rapidsnark/prover"
	"github.com/stretchr/testify/assert"
)

func (s *E2ETestSuite) TestZeto_nf_anon_SuccessfulProving() {
	// s.T().Skip()
	calc, provingKey, _, err := common.LoadCircuit("nf_anon")
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), calc)

	sender := testutils.NewKeypair()
	receiver := testutils.NewKeypair()

	tokenId := big.NewInt(1001)
	tokenUri, err := utxo.HashTokenUri("https://example.com/token/1001")
	assert.NoError(s.T(), err)

	salt1 := crypto.NewSalt()
	input1, err := poseidon.Hash([]*big.Int{tokenId, tokenUri, salt1, sender.PublicKey.X, sender.PublicKey.Y})
	assert.NoError(s.T(), err)

	salt3 := crypto.NewSalt()
	output1, err := poseidon.Hash([]*big.Int{tokenId, tokenUri, salt3, receiver.PublicKey.X, receiver.PublicKey.Y})
	assert.NoError(s.T(), err)

	witnessInputs := map[string]interface{}{
		"tokenIds":              []*big.Int{tokenId},
		"tokenUris":             []*big.Int{tokenUri},
		"inputCommitments":      []*big.Int{input1},
		"inputSalts":            []*big.Int{salt1},
		"inputOwnerPrivateKey":  sender.PrivateKeyBigInt,
		"outputCommitments":     []*big.Int{output1},
		"outputSalts":           []*big.Int{salt3},
		"outputOwnerPublicKeys": [][]*big.Int{{receiver.PublicKey.X, receiver.PublicKey.Y}},
	}

	// calculate the witness object for checking correctness
	witness, err := calc.CalculateWitness(witnessInputs, true)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), witness)

	assert.Equal(s.T(), 0, witness[0].Cmp(big.NewInt(1)))
	assert.Equal(s.T(), 0, witness[1].Cmp(input1))
	assert.Equal(s.T(), 0, witness[2].Cmp(output1))
	assert.Equal(s.T(), 0, witness[3].Cmp(tokenId))
	assert.Equal(s.T(), 0, witness[4].Cmp(tokenUri))

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
	assert.Equal(s.T(), 2, len(proof.PubSignals))

}

func (s *E2ETestSuite) TestZeto_nf_anon_SuccessfulProvingWithConcurrency() {
	// s.T().Skip()
	concurrency := 10
	resultChan := make(chan struct{}, concurrency)

	for i := 0; i < concurrency; i++ {
		index := i
		go func() {
			defer func() {
				resultChan <- struct{}{}
			}()
			calc, provingKey, _, err := common.LoadCircuit("nf_anon")
			assert.NoError(s.T(), err)
			assert.NotNil(s.T(), calc)

			sender := testutils.NewKeypair()
			receiver := testutils.NewKeypair()

			tokenId := big.NewInt(int64(index + 1)) // ensure different token uris for each run
			tokenUri, err := utxo.HashTokenUri("https://example.com/token/" + tokenId.String())
			assert.NoError(s.T(), err)

			salt1 := crypto.NewSalt()
			input1, err := poseidon.Hash([]*big.Int{tokenId, tokenUri, salt1, sender.PublicKey.X, sender.PublicKey.Y})
			assert.NoError(s.T(), err)

			salt3 := crypto.NewSalt()
			output1, err := poseidon.Hash([]*big.Int{tokenId, tokenUri, salt3, receiver.PublicKey.X, receiver.PublicKey.Y})
			assert.NoError(s.T(), err)

			witnessInputs := map[string]interface{}{
				"tokenIds":              []*big.Int{tokenId},
				"tokenUris":             []*big.Int{tokenUri},
				"inputCommitments":      []*big.Int{input1},
				"inputSalts":            []*big.Int{salt1},
				"inputOwnerPrivateKey":  sender.PrivateKeyBigInt,
				"outputCommitments":     []*big.Int{output1},
				"outputSalts":           []*big.Int{salt3},
				"outputOwnerPublicKeys": [][]*big.Int{{receiver.PublicKey.X, receiver.PublicKey.Y}},
			}
			// calculate the witness object for checking correctness
			witness, err := calc.CalculateWitness(witnessInputs, true)
			assert.NoError(s.T(), err)
			assert.NotNil(s.T(), witness)

			assert.Equal(s.T(), 0, witness[0].Cmp(big.NewInt(1)))
			assert.Equal(s.T(), 0, witness[1].Cmp(input1))
			assert.Equal(s.T(), 0, witness[2].Cmp(output1))
			assert.Equal(s.T(), 0, witness[3].Cmp(tokenId))
			assert.Equal(s.T(), 0, witness[4].Cmp(tokenUri))

			// generate the witness binary to feed into the prover
			startTime := time.Now()
			witnessBin, err := calc.CalculateWTNSBin(witnessInputs, true)
			assert.NoError(s.T(), err)
			assert.NotNil(s.T(), witnessBin)

			proof, err := prover.Groth16Prover(provingKey, witnessBin)
			elapsedTime := time.Since(startTime)
			fmt.Printf("Proving time: %s\n", elapsedTime)
			fmt.Printf("token uri from witness: %s\n", witness[3])
			assert.NoError(s.T(), err)
			assert.Equal(s.T(), 3, len(proof.Proof.A))
			assert.Equal(s.T(), 3, len(proof.Proof.B))
			assert.Equal(s.T(), 3, len(proof.Proof.C))
			assert.Equal(s.T(), 2, len(proof.PubSignals))

		}()
	}
	count := 0
	for {
		<-resultChan
		count++
		if count == concurrency {
			break
		}
	}

}
