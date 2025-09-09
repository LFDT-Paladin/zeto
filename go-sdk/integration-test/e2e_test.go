// Copyright © 2024 Kaleido, Inc.
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
	"os"
	"path"
	"testing"

	"github.com/hyperledger-labs/zeto/go-sdk/internal/testutils"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/crypto"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/sparse-merkle-tree/core"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/sparse-merkle-tree/node"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/sparse-merkle-tree/smt"
	"github.com/hyperledger/firefly-signer/pkg/keystorev3"
	"github.com/hyperledger/firefly-signer/pkg/secp256k1"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-rapidsnark/witness/v2"
	"github.com/iden3/go-rapidsnark/witness/wasmer"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"gorm.io/gorm"
)

const MAX_HEIGHT = 64

func loadCircuit(circuitName string) (witness.Calculator, []byte, error) {
	circuitRoot, exists := os.LookupEnv("CIRCUITS_ROOT")
	if !exists {
		return nil, []byte{}, fmt.Errorf("CIRCUITS_ROOT not set")
	}
	provingKeysRoot, exists := os.LookupEnv("PROVING_KEYS_ROOT")
	if !exists {
		return nil, []byte{}, fmt.Errorf("PROVING_KEYS_ROOT not set")
	}

	// load the wasm file for the circuit
	wasmBytes, err := os.ReadFile(path.Join(circuitRoot, fmt.Sprintf("%s_js", circuitName), fmt.Sprintf("%s.wasm", circuitName)))
	if err != nil {
		return nil, []byte{}, err
	}

	// create the prover
	zkeyBytes, err := os.ReadFile(path.Join(provingKeysRoot, fmt.Sprintf("%s.zkey", circuitName)))
	if err != nil {
		return nil, []byte{}, err
	}

	// create the calculator
	var ops []witness.Option
	ops = append(ops, witness.WithWasmEngine(wasmer.NewCircom2WitnessCalculator))
	calc, err := witness.NewCalculator(wasmBytes, ops...)
	if err != nil {
		return nil, []byte{}, err
	}

	return calc, zkeyBytes, err
}

func decryptKeyStorev3(t *testing.T) *secp256k1.KeyPair {
	// this would be read from a keystore file. The same file is used to persist
	// a private key for the secp256k1 curve
	const sampleWallet = `{
		"address": "5d093e9b41911be5f5c4cf91b108bac5d130fa83",
		"crypto": {
			"cipher": "aes-128-ctr",
			"ciphertext": "a28e5f6fd3189ef220f658392af0e967f17931530ac5b79376ed5be7d8adfb5a",
			"cipherparams": {
			"iv": "7babf856e25f812d9dbc133e3122a1fc"
			},
			"kdf": "scrypt",
			"kdfparams": {
			"dklen": 32,
			"n": 262144,
			"p": 1,
			"r": 8,
			"salt": "2844947e39e03785cad3ccda776279dbf5a86a5df9cb6d0ab5773bfcb7cbe3b7"
			},
			"mac": "69ed15cbb03a29ec194bdbd2c2d8084c62be620d5b3b0f668ed9aa1f45dbaf99"
		},
		"id": "307cc063-2344-426a-b992-3b72d5d5be0b",
		"version": 3
	}`

	w, err := keystorev3.ReadWalletFile([]byte(sampleWallet), []byte("correcthorsebatterystaple"))
	assert.NoError(t, err)
	keypair := w.KeyPair()
	return keypair
}

type Signals struct {
	inputValues           []*big.Int
	inputSalts            []*big.Int
	inputCommitments      []*big.Int
	nullifiers            []*big.Int
	outputValues          []*big.Int
	outputSalts           []*big.Int
	outputCommitments     []*big.Int
	outputOwnerPublicKeys [][]*big.Int
	merkleProofs          [][]*big.Int
	enabled               []*big.Int
	root                  *big.Int
}

type E2ETestSuite struct {
	suite.Suite
	db     core.Storage
	dbfile *os.File
	gormDB *gorm.DB

	sender   *testutils.User
	receiver *testutils.User

	regularTest *Signals
	batchTest   *Signals
}

func (s *E2ETestSuite) SetupSuite() {
	logrus.SetLevel(logrus.DebugLevel)
	s.dbfile, s.db, s.gormDB, _ = newSqliteStorage(s.T())
}

func (s *E2ETestSuite) TearDownSuite() {
	err := os.Remove(s.dbfile.Name())
	assert.NoError(s.T(), err)
}

func (s *E2ETestSuite) SetupTest() {
	sender := testutils.NewKeypair()
	receiver := testutils.NewKeypair()
	s.sender = sender
	s.receiver = receiver

	// setup the signals for the regular circuits with 2 inputs and 2 outputs
	s.regularTest = &Signals{
		inputValues:  []*big.Int{big.NewInt(30), big.NewInt(40)},
		outputValues: []*big.Int{big.NewInt(32), big.NewInt(38)},
	}

	salt1 := crypto.NewSalt()
	input1, _ := poseidon.Hash([]*big.Int{s.regularTest.inputValues[0], salt1, sender.PublicKey.X, sender.PublicKey.Y})
	salt2 := crypto.NewSalt()
	input2, _ := poseidon.Hash([]*big.Int{s.regularTest.inputValues[1], salt2, sender.PublicKey.X, sender.PublicKey.Y})
	s.regularTest.inputCommitments = []*big.Int{input1, input2}
	s.regularTest.inputSalts = []*big.Int{salt1, salt2}

	nullifier1, _ := poseidon.Hash([]*big.Int{s.regularTest.inputValues[0], salt1, sender.PrivateKeyBigInt})
	nullifier2, _ := poseidon.Hash([]*big.Int{s.regularTest.inputValues[1], salt2, sender.PrivateKeyBigInt})
	s.regularTest.nullifiers = []*big.Int{nullifier1, nullifier2}

	s.regularTest.merkleProofs, s.regularTest.enabled, s.regularTest.root = buildMerkleProofs(s.regularTest.inputCommitments, s.db, s.T())

	salt3 := crypto.NewSalt()
	output1, _ := poseidon.Hash([]*big.Int{s.regularTest.outputValues[0], salt3, receiver.PublicKey.X, receiver.PublicKey.Y})
	salt4 := crypto.NewSalt()
	output2, _ := poseidon.Hash([]*big.Int{s.regularTest.outputValues[1], salt4, sender.PublicKey.X, sender.PublicKey.Y})
	s.regularTest.outputCommitments = []*big.Int{output1, output2}
	s.regularTest.outputSalts = []*big.Int{salt3, salt4}

	s.regularTest.outputOwnerPublicKeys = [][]*big.Int{{s.receiver.PublicKey.X, receiver.PublicKey.Y}, {sender.PublicKey.X, sender.PublicKey.Y}}

	// setup the signals for the batch circuits with 10 inputs and 10 outputs
	s.batchTest = &Signals{
		inputValues:  []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4), big.NewInt(5), big.NewInt(6), big.NewInt(7), big.NewInt(8), big.NewInt(9), big.NewInt(10)},
		outputValues: []*big.Int{big.NewInt(10), big.NewInt(9), big.NewInt(8), big.NewInt(7), big.NewInt(6), big.NewInt(5), big.NewInt(4), big.NewInt(3), big.NewInt(2), big.NewInt(1)},
	}

	s.batchTest.inputCommitments = make([]*big.Int, 0, 10)
	s.batchTest.inputSalts = make([]*big.Int, 0, 10)
	for _, value := range s.batchTest.inputValues {
		salt := crypto.NewSalt()
		commitment, _ := poseidon.Hash([]*big.Int{value, salt, sender.PublicKey.X, sender.PublicKey.Y})
		s.batchTest.inputCommitments = append(s.batchTest.inputCommitments, commitment)
		s.batchTest.inputSalts = append(s.batchTest.inputSalts, salt)
	}

	s.batchTest.nullifiers = make([]*big.Int, 0, 10)
	for i, value := range s.batchTest.inputValues {
		salt := s.batchTest.inputSalts[i]
		nullifier, _ := poseidon.Hash([]*big.Int{value, salt, sender.PrivateKeyBigInt})
		s.batchTest.nullifiers = append(s.batchTest.nullifiers, nullifier)
	}

	s.batchTest.merkleProofs, s.batchTest.enabled, s.batchTest.root = buildMerkleProofs(s.batchTest.inputCommitments, s.db, s.T())

	s.batchTest.outputCommitments = make([]*big.Int, 0, 10)
	s.batchTest.outputSalts = make([]*big.Int, 0, 10)
	for _, value := range s.batchTest.outputValues {
		salt := crypto.NewSalt()
		commitment, _ := poseidon.Hash([]*big.Int{value, salt, receiver.PublicKey.X, receiver.PublicKey.Y})
		s.batchTest.outputCommitments = append(s.batchTest.outputCommitments, commitment)
		s.batchTest.outputSalts = append(s.batchTest.outputSalts, salt)
	}

	s.batchTest.outputOwnerPublicKeys = make([][]*big.Int, 0, 10)
	for i := 0; i < 10; i++ {
		s.batchTest.outputOwnerPublicKeys = append(s.batchTest.outputOwnerPublicKeys, []*big.Int{receiver.PublicKey.X, receiver.PublicKey.Y})
	}

}

func buildMerkleProofs(inputCommitments []*big.Int, db core.Storage, t *testing.T) ([][]*big.Int, []*big.Int, *big.Int) {
	mt, err := smt.NewMerkleTree(db, MAX_HEIGHT)
	assert.NoError(t, err)

	for _, commitment := range inputCommitments {
		idx, _ := node.NewNodeIndexFromBigInt(commitment)
		utxo := node.NewIndexOnly(idx)
		n, err := node.NewLeafNode(utxo)
		assert.NoError(t, err)
		err = mt.AddLeaf(n)
		assert.NoError(t, err)
	}

	root := mt.Root().BigInt()

	proofs, _, err := mt.GenerateProofs(inputCommitments, nil)
	assert.NoError(t, err)

	smtProofs := make([][]*big.Int, len(proofs))
	enabled := make([]*big.Int, len(proofs))
	for i, proof := range proofs {
		circomProof, err := proof.ToCircomVerifierProof(inputCommitments[i], inputCommitments[i], mt.Root(), MAX_HEIGHT)
		assert.NoError(t, err)
		proofSiblings := make([]*big.Int, len(circomProof.Siblings)-1)
		for i, s := range circomProof.Siblings[0 : len(circomProof.Siblings)-1] {
			proofSiblings[i] = s.BigInt()
		}
		smtProofs[i] = proofSiblings
		enabled[i] = big.NewInt(1)
	}

	return smtProofs, enabled, root
}

func TestE2ETestSuite(t *testing.T) {
	suite.Run(t, new(E2ETestSuite))
}
