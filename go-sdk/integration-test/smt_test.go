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
	"math/big"
	"math/rand"
	"os"
	"testing"

	"github.com/hyperledger-labs/zeto/go-sdk/integration-test/common"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/sparse-merkle-tree/node"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/sparse-merkle-tree/smt"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type SmtTestSuite struct {
	suite.Suite
}

func (s *SmtTestSuite) TestConcurrentLeafnodesInsertion() {
	logrus.SetLevel(logrus.DebugLevel)
	x, _ := new(big.Int).SetString("9198063289874244593808956064764348354864043212453245695133881114917754098693", 10)
	y, _ := new(big.Int).SetString("3600411115173311692823743444460566395943576560299970643507632418781961416843", 10)
	alice := &babyjub.PublicKey{
		X: x,
		Y: y,
	}

	values := []int{10, 20, 30, 40}
	salts := []string{
		"43c49e8ba68a9b8a6bb5c230a734d8271a83d2f63722e7651272ebeef5446e",
		"19b965f7629e4f0c4bd0b8f9c87f17580f18a32a31b4641550071ee4916bbbfc",
		"9b0b93df975547e430eabff085a77831b8fcb6b5396e6bb815fda8d14125370",
		"194ec10ec96a507c7c9b60df133d13679b874b0bd6ab89920135508f55b3f064",
	}

	// run the test 10 times
	for i := 0; i < 100; i++ {
		// shuffle the utxos for this run
		for i := range values {
			j := rand.Intn(i + 1)
			values[i], values[j] = values[j], values[i]
			salts[i], salts[j] = salts[j], salts[i]
		}

		testConcurrentInsertion(s.T(), alice, values, salts)
	}
}

func testConcurrentInsertion(t *testing.T, alice *babyjub.PublicKey, values []int, salts []string) {
	dbfile, db, _, _ := common.NewSqliteStorage(t)
	defer func() {
		err := os.Remove(dbfile.Name())
		assert.NoError(t, err)
	}()

	mt, err := smt.NewMerkleTree(db, common.MAX_HEIGHT)
	assert.NoError(t, err)
	done := make(chan bool, len(values))

	for i, v := range values {
		go func(i, v int) {
			salt, _ := new(big.Int).SetString(salts[i], 16)
			utxo := node.NewFungible(big.NewInt(int64(v)), alice, salt)
			n, err := node.NewLeafNode(utxo)
			assert.NoError(t, err)
			err = mt.AddLeaf(n)
			assert.NoError(t, err)
			done <- true
		}(i, v)
	}

	for i := 0; i < len(values); i++ {
		<-done
	}

	assert.Equal(t, "abacf46f5217552ee28fe50b8fd7ca6aa46daeb9acf9f60928654c3b1a472f23", mt.Root().Hex())
}

func TestSmtTestSuite(t *testing.T) {
	suite.Run(t, new(SmtTestSuite))
}
