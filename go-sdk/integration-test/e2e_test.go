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
	"os"
	"testing"

	"github.com/hyperledger-labs/zeto/go-sdk/integration-test/common"
	"github.com/hyperledger-labs/zeto/go-sdk/internal/testutils"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/sparse-merkle-tree/core"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/sparse-merkle-tree/smt"
	"github.com/hyperledger/firefly-signer/pkg/keystorev3"
	"github.com/hyperledger/firefly-signer/pkg/secp256k1"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"gorm.io/gorm"
)

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

type E2ETestSuite struct {
	suite.Suite
	db     core.Storage
	dbfile *os.File
	gormDB *gorm.DB

	sender   *testutils.User
	receiver *testutils.User

	regularTest *common.Signals
	batchTest   *common.Signals
}

func (s *E2ETestSuite) SetupSuite() {
	logrus.SetLevel(logrus.DebugLevel)
	s.dbfile, s.db, s.gormDB, _ = common.NewSqliteStorage(s.T())
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
	s.regularTest = common.NewSignals(sender, receiver, false, s.db, s.T())
	mt, err := smt.NewMerkleTree(s.db, common.MAX_HEIGHT)
	assert.NoError(s.T(), err)
	for _, commitment := range s.regularTest.InputCommitments {
		common.AddCommitmentToMerkleTree(mt, commitment, s.T())
	}
	for _, commitment := range s.regularTest.OutputCommitments {
		common.AddCommitmentToMerkleTree(mt, commitment, s.T())
	}
	s.regularTest.MerkleProofs, s.regularTest.Enabled, s.regularTest.Root = common.BuildMerkleProofs(s.regularTest.InputCommitments, s.db, s.T())

	// setup the signals for the batch circuits with 10 inputs and 10 outputs
	s.batchTest = common.NewSignals(sender, receiver, true, s.db, s.T())
	for _, commitment := range s.batchTest.InputCommitments {
		common.AddCommitmentToMerkleTree(mt, commitment, s.T())
	}
	for _, commitment := range s.batchTest.OutputCommitments {
		common.AddCommitmentToMerkleTree(mt, commitment, s.T())
	}
	s.batchTest.MerkleProofs, s.batchTest.Enabled, s.batchTest.Root = common.BuildMerkleProofs(s.batchTest.InputCommitments, s.db, s.T())
}

func TestE2ETestSuite(t *testing.T) {
	suite.Run(t, new(E2ETestSuite))
}
