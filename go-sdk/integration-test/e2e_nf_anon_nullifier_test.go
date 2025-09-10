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
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/sparse-merkle-tree/node"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/sparse-merkle-tree/smt"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/utxo"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-rapidsnark/prover"
	"github.com/stretchr/testify/assert"
)

func (s *E2ETestSuite) TestZeto_nf_anon_nullifier_SuccessfulProving() {
	// s.T().Skip()
	calc, provingKey, err := common.LoadCircuit("nf_anon_nullifier_transfer")
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), calc)

	sender := testutils.NewKeypair()
	receiver := testutils.NewKeypair()

	tokenId := big.NewInt(1001)
	uriString := "https://example.com/token/1001"
	tokenUri, err := utxo.HashTokenUri(uriString)
	assert.NoError(s.T(), err)

	salt1 := crypto.NewSalt()
	input1, err := poseidon.Hash([]*big.Int{tokenId, tokenUri, salt1, sender.PublicKey.X, sender.PublicKey.Y})
	assert.NoError(s.T(), err)

	nullifier1, _ := poseidon.Hash([]*big.Int{tokenId, tokenUri, salt1, sender.PrivateKeyBigInt})

	mt, err := smt.NewMerkleTree(s.db, common.MAX_HEIGHT)
	assert.NoError(s.T(), err)
	utxo1 := node.NewNonFungible(tokenId, uriString, sender.PublicKey, salt1)
	n1, err := node.NewLeafNode(utxo1)
	assert.NoError(s.T(), err)
	err = mt.AddLeaf(n1)
	assert.NoError(s.T(), err)
	proofs, _, err := mt.GenerateProofs([]*big.Int{input1}, nil)
	assert.NoError(s.T(), err)
	circomProof1, err := proofs[0].ToCircomVerifierProof(input1, input1, mt.Root(), common.MAX_HEIGHT)
	assert.NoError(s.T(), err)
	proof1Siblings := make([]*big.Int, len(circomProof1.Siblings)-1)
	for i, s := range circomProof1.Siblings[0 : len(circomProof1.Siblings)-1] {
		proof1Siblings[i] = s.BigInt()
	}

	salt3 := crypto.NewSalt()
	output1, err := poseidon.Hash([]*big.Int{tokenId, tokenUri, salt3, receiver.PublicKey.X, receiver.PublicKey.Y})
	assert.NoError(s.T(), err)

	witnessInputs := map[string]interface{}{
		"tokenId":              tokenId,
		"tokenUri":             tokenUri,
		"nullifier":            nullifier1,
		"inputCommitment":      input1,
		"inputSalt":            salt1,
		"inputOwnerPrivateKey": sender.PrivateKeyBigInt,
		"root":                 mt.Root().BigInt(),
		"merkleProof":          proof1Siblings,
		"outputCommitment":     output1,
		"outputSalt":           salt3,
		"outputOwnerPublicKey": []*big.Int{receiver.PublicKey.X, receiver.PublicKey.Y},
	}

	// calculate the witness object for checking correctness
	witness, err := calc.CalculateWitness(witnessInputs, true)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), witness)

	assert.Equal(s.T(), 0, witness[0].Cmp(big.NewInt(1)))
	assert.Equal(s.T(), 0, witness[1].Cmp(nullifier1))

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
