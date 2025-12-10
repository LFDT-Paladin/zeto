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
	"os"
	"testing"

	"github.com/hyperledger-labs/zeto/go-sdk/integration-test/common"
	"github.com/hyperledger-labs/zeto/go-sdk/internal/crypto/hash"
	"github.com/hyperledger-labs/zeto/go-sdk/internal/testutils"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/crypto"

	"github.com/hyperledger-labs/zeto/go-sdk/pkg/sparse-merkle-tree/core"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/sparse-merkle-tree/node"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/sparse-merkle-tree/smt"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/sparse-merkle-tree/storage"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type SqliteTestSuite struct {
	suite.Suite
	db      core.Storage
	dbfile  *os.File
	gormDB  *gorm.DB
	smtName string
}

func (s *SqliteTestSuite) SetupTest() {
	logrus.SetLevel(logrus.DebugLevel)
	s.dbfile, s.db, s.gormDB, s.smtName = common.NewSqliteStorage(s.T())
}

func (s *SqliteTestSuite) TearDownTest() {
	err := os.Remove(s.dbfile.Name())
	assert.NoError(s.T(), err)
}

func (s *SqliteTestSuite) TestSqliteStorage() {
	hasher := crypto.NewPoseidonHasher()
	mt, err := smt.NewMerkleTree(s.db, common.MAX_HEIGHT)
	assert.NoError(s.T(), err)

	tokenId := big.NewInt(1001)
	uriString := "https://example.com/token/1001"
	assert.NoError(s.T(), err)
	sender := testutils.NewKeypair()
	salt1 := crypto.NewSalt()

	utxo1 := node.NewNonFungible(tokenId, uriString, sender.PublicKey, salt1, hasher)
	n1, err := node.NewLeafNode(utxo1, nil, hasher)
	assert.NoError(s.T(), err)
	err = mt.AddLeaf(n1)
	assert.NoError(s.T(), err)

	root := mt.Root()
	dbRoot := core.SMTRoot{Name: s.smtName}
	err = s.gormDB.Table(core.TreeRootsTable).First(&dbRoot).Error
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), root.Hex(), dbRoot.RootRef)

	dbNode := core.SMTNode{RefKey: n1.Ref().Hex()}
	err = s.gormDB.Table(core.NodesTablePrefix + s.smtName).First(&dbNode).Error
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), n1.Ref().Hex(), dbNode.RefKey)
}

func TestSqliteStorage(t *testing.T) {
	suite.Run(t, new(SqliteTestSuite))
}

func TestPostgresStorage(t *testing.T) {
	dsn := "host=localhost user=postgres password=my-secret dbname=postgres port=5432 sslmode=disable"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	assert.NoError(t, err)
	err = db.Table(core.TreeRootsTable).AutoMigrate(&core.SMTRoot{})
	assert.NoError(t, err)
	err = db.Table(core.NodesTablePrefix + "test_1").AutoMigrate(&core.SMTNode{})
	assert.NoError(t, err)

	defer func() {
		// Table name needs to be wrapped in quotes if not it will be lowercased
		tx := db.Exec("DROP TABLE " + "\"" + core.TreeRootsTable + "\"")
		assert.NoError(t, tx.Error)
		tx = db.Exec("DROP TABLE " + "\"" + core.NodesTablePrefix + "test_1\"")
		assert.NoError(t, tx.Error)
	}()

	provider := &common.TestSqlProvider{Db: db}
	s, err := storage.NewSqlStorage(provider, "test_1", &hash.PoseidonHasher{})
	assert.NoError(t, err)

	hasher := crypto.NewPoseidonHasher()
	mt, err := smt.NewMerkleTree(s, common.MAX_HEIGHT)
	assert.NoError(t, err)

	tokenId := big.NewInt(1001)
	tokenUri := "https://example.com/token/1001"
	assert.NoError(t, err)
	sender := testutils.NewKeypair()
	salt1 := crypto.NewSalt()

	utxo1 := node.NewNonFungible(tokenId, tokenUri, sender.PublicKey, salt1, hasher)
	n1, err := node.NewLeafNode(utxo1, nil, hasher)
	assert.NoError(t, err)
	err = mt.AddLeaf(n1)
	assert.NoError(t, err)

	root := mt.Root()
	dbRoot := core.SMTRoot{Name: "test_1"}
	err = db.Table(core.TreeRootsTable).First(&dbRoot).Error
	assert.NoError(t, err)
	assert.Equal(t, root.Hex(), dbRoot.RootRef)

	dbNode := core.SMTNode{RefKey: n1.Ref().Hex()}
	err = db.Table(core.NodesTablePrefix + "test_1").First(&dbNode).Error
	assert.NoError(t, err)
	assert.Equal(t, n1.Ref().Hex(), dbNode.RefKey)
}
