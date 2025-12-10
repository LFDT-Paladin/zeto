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

package storage

import (
	"math/big"
	"os"
	"testing"

	"github.com/hyperledger-labs/zeto/go-sdk/internal/crypto"
	"github.com/hyperledger-labs/zeto/go-sdk/internal/crypto/hash"
	"github.com/hyperledger-labs/zeto/go-sdk/internal/sparse-merkle-tree/node"
	"github.com/hyperledger-labs/zeto/go-sdk/internal/testutils"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/sparse-merkle-tree/core"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type testSqlProvider struct {
	db *gorm.DB
}

func (s *testSqlProvider) DB() *gorm.DB {
	return s.db
}

func (s *testSqlProvider) Close() {}

func TestSqliteStorage(t *testing.T) {
	dbfile, err := os.CreateTemp("", "gorm.db")
	assert.NoError(t, err)
	defer func() {
		os.Remove(dbfile.Name())
	}()
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{})
	assert.NoError(t, err)
	err = db.Table(core.TreeRootsTable).AutoMigrate(&core.SMTRoot{})
	assert.NoError(t, err)
	err = db.Table(core.NodesTablePrefix + "test_1").AutoMigrate(&core.SMTNode{})
	assert.NoError(t, err)

	provider := &testSqlProvider{db: db}
	s := NewSqlStorage(provider, "test_1", &hash.PoseidonHasher{})
	assert.NoError(t, err)

	tokenId := big.NewInt(1001)
	uriString := "https://example.com/token/1001"
	assert.NoError(t, err)
	sender := testutils.NewKeypair()
	salt1 := crypto.NewSalt()

	utxo1 := node.NewNonFungible(tokenId, uriString, sender.PublicKey, salt1, &hash.PoseidonHasher{})
	n1, err := node.NewLeafNode(utxo1, nil)
	assert.NoError(t, err)

	idx, _ := utxo1.CalculateIndex()
	err = s.UpsertRootNodeRef(idx)
	assert.NoError(t, err)
	dbIdx, err := s.GetRootNodeRef()
	assert.NoError(t, err)
	assert.Equal(t, idx.Hex(), dbIdx.Hex())

	dbRoot := core.SMTRoot{Name: "test_1"}
	err = db.Table(core.TreeRootsTable).First(&dbRoot).Error
	assert.NoError(t, err)
	assert.Equal(t, idx.Hex(), dbRoot.RootRef)

	err = s.InsertNode(n1)
	assert.NoError(t, err)

	dbNode := core.SMTNode{RefKey: n1.Ref().Hex()}
	err = db.Table(core.NodesTablePrefix + "test_1").First(&dbNode).Error
	assert.NoError(t, err)
	assert.Equal(t, n1.Ref().Hex(), dbNode.RefKey)

	n2, err := s.GetNode(n1.Ref())
	assert.NoError(t, err)
	assert.Equal(t, n1.Ref().Hex(), n2.Ref().Hex())

	bn1, err := node.NewBranchNode(n1.Ref(), n1.Ref(), &hash.PoseidonHasher{})
	assert.NoError(t, err)
	err = s.InsertNode(bn1)
	assert.NoError(t, err)

	n3, err := s.GetNode(bn1.Ref())
	assert.NoError(t, err)
	assert.Equal(t, bn1.Ref().Hex(), n3.Ref().Hex())
}

func TestSqliteStorageFail_NoRootTable(t *testing.T) {
	dbfile, err := os.CreateTemp("", "gorm.db")
	assert.NoError(t, err)
	defer func() {
		os.Remove(dbfile.Name())
	}()
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{})
	assert.NoError(t, err)

	provider := &testSqlProvider{db: db}
	s := NewSqlStorage(provider, "test_1", &hash.PoseidonHasher{})
	assert.NoError(t, err)

	_, err = s.GetRootNodeRef()
	assert.EqualError(t, err, "no such table: merkelTreeRoots")

	err = db.Table(core.TreeRootsTable).AutoMigrate(&core.SMTRoot{})
	assert.NoError(t, err)

	_, err = s.GetRootNodeRef()
	assert.EqualError(t, err, "key not found")
}

func TestSqliteStorageFail_NoNodeTable(t *testing.T) {
	dbfile, err := os.CreateTemp("", "gorm.db")
	assert.NoError(t, err)
	defer func() {
		os.Remove(dbfile.Name())
	}()
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{})
	assert.NoError(t, err)

	provider := &testSqlProvider{db: db}
	s := NewSqlStorage(provider, "test_1", &hash.PoseidonHasher{})
	assert.NoError(t, err)

	idx, err := node.NewNodeIndexFromHex("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", &hash.PoseidonHasher{})
	assert.NoError(t, err)
	_, err = s.GetNode(idx)
	assert.EqualError(t, err, "no such table: smtNodes_test_1")

	err = db.Table(core.NodesTablePrefix + "test_1").AutoMigrate(&core.SMTNode{})
	assert.NoError(t, err)

	_, err = s.GetNode(idx)
	assert.EqualError(t, err, "key not found")
}

func TestSqliteStorageFail_BadNodeIndex(t *testing.T) {
	dbfile, err := os.CreateTemp("", "gorm.db")
	assert.NoError(t, err)
	defer func() {
		os.Remove(dbfile.Name())
	}()
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{})
	assert.NoError(t, err)
	err = db.Table(core.TreeRootsTable).AutoMigrate(&core.SMTRoot{})
	assert.NoError(t, err)
	err = db.Table(core.NodesTablePrefix + "test_1").AutoMigrate(&core.SMTNode{})
	assert.NoError(t, err)

	provider := &testSqlProvider{db: db}
	s := NewSqlStorage(provider, "test_1", &hash.PoseidonHasher{})
	assert.NoError(t, err)

	sender := testutils.NewKeypair()
	salt1 := crypto.NewSalt()

	utxo1 := node.NewFungible(big.NewInt(100), sender.PublicKey, salt1, &hash.PoseidonHasher{})
	n1, err := node.NewLeafNode(utxo1, nil)
	assert.NoError(t, err)
	err = s.InsertNode(n1)
	assert.NoError(t, err)

	// modify the index in the db
	dbNode := core.SMTNode{RefKey: n1.Ref().Hex()}
	err = db.Table(core.NodesTablePrefix + "test_1").First(&dbNode).Error
	assert.NoError(t, err)
	badIndex := ""
	dbNode.Index = &badIndex
	err = db.Table(core.NodesTablePrefix + "test_1").Save(&dbNode).Error
	assert.NoError(t, err)

	_, err = s.GetNode(n1.Ref())
	assert.EqualError(t, err, "expected 32 bytes for the decoded node index")

	bn1, err := node.NewBranchNode(n1.Ref(), n1.Ref(), &hash.PoseidonHasher{})
	assert.NoError(t, err)
	err = s.InsertNode(bn1)
	assert.NoError(t, err)

	dbNode = core.SMTNode{RefKey: bn1.Ref().Hex()}
	err = db.Table(core.NodesTablePrefix + "test_1").First(&dbNode).Error
	assert.NoError(t, err)
	saveLeftChild := *dbNode.LeftChild
	dbNode.LeftChild = &badIndex
	err = db.Table(core.NodesTablePrefix + "test_1").Save(&dbNode).Error
	assert.NoError(t, err)

	_, err = s.GetNode(bn1.Ref())
	assert.EqualError(t, err, "expected 32 bytes for the decoded node index")

	dbNode.LeftChild = &saveLeftChild
	dbNode.RightChild = &badIndex
	err = db.Table(core.NodesTablePrefix + "test_1").Save(&dbNode).Error
	assert.NoError(t, err)
	_, err = s.GetNode(bn1.Ref())
	assert.EqualError(t, err, "expected 32 bytes for the decoded node index")

	s.Close()
}
