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
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-rapidsnark/prover"
	"github.com/stretchr/testify/assert"
)

func (s *E2ETestSuite) TestZeto_anon_enc_SuccessfulProving() {
	// s.T().Skip()
	calc, provingKey, err := common.LoadCircuit("anon_enc")
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), calc)

	encryptionNonce := crypto.NewEncryptionNonce()
	ephemeralKeypair := testutils.NewKeypair()

	witnessInputs := map[string]interface{}{
		"inputCommitments":      s.regularTest.InputCommitments,
		"inputValues":           s.regularTest.InputValues,
		"inputSalts":            s.regularTest.InputSalts,
		"inputOwnerPrivateKey":  s.sender.PrivateKeyBigInt,
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
	assert.Equal(s.T(), 15, len(proof.PubSignals))

	// the receiver would be able to get the encrypted values and salts
	// from the transaction events
	encryptedValues := make([]*big.Int, 4)
	for i := 0; i < 4; i++ {
		v, ok := new(big.Int).SetString(proof.PubSignals[i+2], 10)
		assert.True(s.T(), ok)
		encryptedValues[i] = v
	}

	// the first two elements in the public signals are the encrypted value and salt
	// for the first output. decrypt using the receiver's private key and compare with
	// the UTXO hash
	secret := crypto.GenerateECDHSharedSecret(s.receiver.PrivateKey, ephemeralKeypair.PublicKey)
	decrypted, err := crypto.PoseidonDecrypt(encryptedValues, []*big.Int{secret.X, secret.Y}, encryptionNonce, 2)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), s.regularTest.OutputValues[0].String(), decrypted[0].String())
	assert.Equal(s.T(), s.regularTest.OutputSalts[0].String(), decrypted[1].String())

	// as the receiver, to check if the decryption was successful, we hash the decrypted
	// value and salt and compare with the output commitment
	calculatedHash, err := poseidon.Hash([]*big.Int{decrypted[0], decrypted[1], s.receiver.PublicKey.X, s.receiver.PublicKey.Y})
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), s.regularTest.OutputCommitments[0].String(), calculatedHash.String())
}
