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
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/cloudflare/circl/kem/mlkem/mlkem512"

	"github.com/hyperledger-labs/zeto/go-sdk/integration-test/common"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/crypto"
	zetoCrypto "github.com/hyperledger-labs/zeto/go-sdk/pkg/crypto"
	"github.com/iden3/go-rapidsnark/prover"
	"github.com/stretchr/testify/assert"
)

func (s *E2ETestSuite) TestZeto_anon_nullifier_qurrency_SuccessfulProving() {
	calc, provingKey, _, err := common.LoadCircuit("anon_nullifier_qurrency_transfer")
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), calc)

	nonce := zetoCrypto.NewEncryptionNonce()
	randomBytes := make([]byte, 32)
	n, _ := rand.Read(randomBytes)
	assert.Equal(s.T(), 32, n, "Expected to read 32 random bytes")
	// convert the randomBytes into a little-endian bit array
	bitArray := zetoCrypto.BytesToBits(randomBytes)
	// convert the bit array into a big.Int array
	randomBits := make([]*big.Int, len(bitArray))
	for i, bit := range bitArray {
		randomBits[i] = big.NewInt(int64(bit))
	}

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
		"encryptionNonce":       nonce,
		"randomness":            randomBits,
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
	assert.Equal(s.T(), 48, len(proof.PubSignals))

	// verify the process for the audit authority to decapsulate the ciphertexts
	// to recover the shared secret and decrypt the output ciphertexts

	// using the same seed as in the test key, saved in 'zkp/js/lib/testKeypair.js'
	seed := []uint8{51, 190, 56, 93, 190, 118, 40, 91, 14, 74, 128, 211, 66, 120, 127, 86, 67, 166, 17, 26, 154, 169, 10, 216, 214, 25, 195, 191, 184, 98, 8, 105, 115, 68, 165, 251, 33, 221, 44, 71, 8, 21, 65, 118, 193, 19, 183, 220, 160, 154, 60, 139, 124, 187, 141, 141, 216, 250, 45, 78, 209, 229, 97, 196}
	_, sk := mlkem512.NewKeyFromSeed(seed)

	mlkemCiphertextStrs := proof.PubSignals[:25]
	mlkemCiphertextBytes, err := zetoCrypto.RecoverMlkemCiphertextBytes(mlkemCiphertextStrs)
	assert.NoError(s.T(), err, "Failed to recover MLKEM ciphertext bytes")
	assert.Equal(s.T(), 768, len(mlkemCiphertextBytes), "MLKEM ciphertext bytes length mismatch")
	// temporary debug to catch the case where the ciphertext bytes are not 768 bytes
	if len(mlkemCiphertextBytes) != 768 {
		fmt.Printf("MLKEM ciphertext bytes length: %d\n", len(mlkemCiphertextBytes))
		fmt.Printf("MLKEM ciphertext strings: %s\n", mlkemCiphertextStrs)
		fmt.Printf("MLKEM ciphertext bytes: %v\n", mlkemCiphertextBytes)
	}

	ss, err := sk.Scheme().Decapsulate(sk, mlkemCiphertextBytes)
	assert.NoError(s.T(), err, "Failed to decapsulate ciphertext")
	assert.Equal(s.T(), 32, len(ss), "Shared secret size mismatch")

	// convert the shared secret bytes to a point on the BabyJub curve
	ssPoint, err := zetoCrypto.PublicKeyFromSeed(ss)
	assert.NoError(s.T(), err, "Failed to convert shared secret to public key")

	// use the recovered shared secret to decrypt the output ciphertexts
	encryptedValueStrs := proof.PubSignals[25:41]
	var encryptedValues []*big.Int
	for _, str := range encryptedValueStrs {
		v, ok := new(big.Int).SetString(str, 10)
		assert.True(s.T(), ok, "Failed to convert hex string to big.Int")
		encryptedValues = append(encryptedValues, v)
	}

	decrypted, err := crypto.PoseidonDecrypt(encryptedValues, []*big.Int{ssPoint.X, ssPoint.Y}, nonce, 14)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), s.sender.PublicKey.X.String(), decrypted[0].String())
	assert.Equal(s.T(), s.sender.PublicKey.Y.String(), decrypted[1].String())
}
