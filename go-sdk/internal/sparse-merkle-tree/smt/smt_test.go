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

package smt

import (
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"os"
	"testing"

	"github.com/hyperledger-labs/zeto/go-sdk/internal/crypto"
	"github.com/hyperledger-labs/zeto/go-sdk/internal/crypto/hash"
	"github.com/hyperledger-labs/zeto/go-sdk/internal/sparse-merkle-tree/node"
	"github.com/hyperledger-labs/zeto/go-sdk/internal/sparse-merkle-tree/storage"
	"github.com/hyperledger-labs/zeto/go-sdk/internal/sparse-merkle-tree/utils"
	"github.com/hyperledger-labs/zeto/go-sdk/internal/testutils"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/sparse-merkle-tree/core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type MerkleTreeTestSuite struct {
	suite.Suite
	dbfile *os.File
	gormDB *gorm.DB
}

type testSqlProvider struct {
	db *gorm.DB
}

func (p *testSqlProvider) DB() *gorm.DB {
	return p.db
}

func (p *testSqlProvider) Close() {}

func (s *MerkleTreeTestSuite) SetupTest() {
	logrus.SetLevel(logrus.DebugLevel)
	dbfile, err := os.CreateTemp("", "gorm.db")
	assert.NoError(s.T(), err)
	s.dbfile = dbfile
	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
		logger.Config{
			LogLevel:                  logger.Info, // Log level
			IgnoreRecordNotFoundError: true,        // Ignore ErrRecordNotFound error for logger
			ParameterizedQueries:      false,       // Don't include params in the SQL log
			Colorful:                  true,        // Disable color
		},
	)
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{Logger: newLogger})
	assert.NoError(s.T(), err)
	err = db.Table(core.TreeRootsTable).AutoMigrate(&core.SMTRoot{})
	assert.NoError(s.T(), err)
	err = db.Table(core.NodesTablePrefix + "test_1").AutoMigrate(&core.SMTNode{})
	assert.NoError(s.T(), err)

	s.gormDB = db
}

func (s *MerkleTreeTestSuite) TearDownTest() {
	err := os.Remove(s.dbfile.Name())
	assert.NoError(s.T(), err)
}

func (s *MerkleTreeTestSuite) TestNewMerkleTree() {
	provider := &testSqlProvider{db: s.gormDB}
	db := storage.NewSqlStorage(provider, "test_1", &hash.PoseidonHasher{})
	mt, err := NewMerkleTree(db, 64)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), 0, mt.Root().BigInt().Cmp(big.NewInt(0)))
}

func (s *MerkleTreeTestSuite) TestAddNode() {
	provider := &testSqlProvider{db: s.gormDB}
	hasher := &hash.PoseidonHasher{}
	db := storage.NewSqlStorage(provider, "test_1", hasher)
	mt, err := NewMerkleTree(db, 64)
	assert.NoError(s.T(), err)

	x, _ := new(big.Int).SetString("9198063289874244593808956064764348354864043212453245695133881114917754098693", 10)
	y, _ := new(big.Int).SetString("3600411115173311692823743444460566395943576560299970643507632418781961416843", 10)
	alice := &babyjub.PublicKey{
		X: x,
		Y: y,
	}
	salt1, _ := new(big.Int).SetString("43c49e8ba68a9b8a6bb5c230a734d8271a83d2f63722e7651272ebeef5446e", 16)
	utxo1 := node.NewFungible(big.NewInt(10), alice, salt1, hasher)
	idx1, err := utxo1.CalculateIndex()
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "11a22e32f5010d3658d1da9c93f26b77afe7a84346f49eae3d1d4fc6cd0a36fd", idx1.BigInt().Text(16))

	n1, err := node.NewLeafNode(utxo1, nil)
	assert.NoError(s.T(), err)
	err = mt.AddLeaf(n1)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "525b60b382630ee7825bea84fb8808c13ede1fb827fe683cd5b14d76f6ac6d0b", mt.Root().Hex())

	// adding a 2nd node to test the tree update and branch nodes
	salt2, _ := new(big.Int).SetString("19b965f7629e4f0c4bd0b8f9c87f17580f18a32a31b4641550071ee4916bbbfc", 16)
	utxo2 := node.NewFungible(big.NewInt(20), alice, salt2, hasher)
	idx2, err := utxo2.CalculateIndex()
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "197b0dc3f167041e03d3eafacec1aa3ab12a0d7a606581af01447c269935e521", idx2.BigInt().Text(16))
	n2, err := node.NewLeafNode(utxo2, nil)
	assert.NoError(s.T(), err)
	err = mt.AddLeaf(n2)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "c432caeb6448cb10bf8b449704f0fc79d84723b5aadeaf6f1b73cf00fe94c22f", mt.Root().Hex())

	// adding a 3rd node to test the tree update and branch nodes with a left/right child node
	salt3, _ := new(big.Int).SetString("9b0b93df975547e430eabff085a77831b8fcb6b5396e6bb815fda8d14125370", 16)
	utxo3 := node.NewFungible(big.NewInt(30), alice, salt3, hasher)
	idx3, err := utxo3.CalculateIndex()
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "2d46e23e813abf1fdabffe3ff22a38ebf6bb92d7c381463bee666eb010289fd5", idx3.BigInt().Text(16))
	n3, err := node.NewLeafNode(utxo3, nil)
	assert.NoError(s.T(), err)
	err = mt.AddLeaf(n3)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "bf8409a4a6c7366bc64c154d3c2f40a8c3c5ddb0f1d47c41336d97ff27640502", mt.Root().Hex())

	// adding a 4th node to test the tree update and branch nodes with the other left/right child node
	salt4, _ := new(big.Int).SetString("194ec10ec96a507c7c9b60df133d13679b874b0bd6ab89920135508f55b3f064", 16)
	utxo4 := node.NewFungible(big.NewInt(40), alice, salt4, hasher)
	idx4, err := utxo4.CalculateIndex()
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "887884c3421b72f8f1991c64808262da78732abf961118d02b0792bd421521f", idx4.BigInt().Text(16))
	n4, err := node.NewLeafNode(utxo4, nil)
	assert.NoError(s.T(), err)
	err = mt.AddLeaf(n4)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "abacf46f5217552ee28fe50b8fd7ca6aa46daeb9acf9f60928654c3b1a472f23", mt.Root().Hex())

	// test storage persistence
	rawDB := mt.(*sparseMerkleTree).db
	rootIdx, err := rawDB.GetRootNodeRef()
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "abacf46f5217552ee28fe50b8fd7ca6aa46daeb9acf9f60928654c3b1a472f23", rootIdx.Hex())
	dbNode1, err := rawDB.GetNode(n1.Ref())
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), n1.Index().Hex(), dbNode1.Index().Hex())

	// test storage persistence across tree creation
	mt2, err := NewMerkleTree(db, 10)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "abacf46f5217552ee28fe50b8fd7ca6aa46daeb9acf9f60928654c3b1a472f23", mt2.Root().Hex())
}

// cross-referenced with the unit tests in iden3/js-merkletree repo
func (s *MerkleTreeTestSuite) TestAddNode_Keccak256_TwoNodes() {
	provider := &testSqlProvider{db: s.gormDB}
	hasher := &hash.Keccak256Hasher{}
	db := storage.NewSqlStorage(provider, "test_1", hasher)
	mt, err := NewMerkleTree(db, 64)
	assert.NoError(s.T(), err)

	// adding first node: i=1, v=2
	i1, _ := node.NewNodeIndexFromBigInt(big.NewInt(1), hasher)
	inode1 := utils.NewIndexOnly(i1)
	v1 := big.NewInt(2)
	n1, err := node.NewLeafNode(inode1, v1)
	assert.NoError(s.T(), err)

	err = mt.AddLeaf(n1)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "2d163ec3852e4a9110862823eb833344b6e15bc64b3e415d5634f5dc79a8fd2c", mt.Root().Hex())
	assert.Equal(s.T(), "20349940423862035287868699599764962454537984981628200184279725786303353984557", mt.Root().BigInt().Text(10))

	// adding second node: i=33, v=44
	i2, _ := node.NewNodeIndexFromBigInt(big.NewInt(33), hasher)
	inode2 := utils.NewIndexOnly(i2)
	v2 := big.NewInt(44)
	n2_, err := node.NewLeafNode(inode2, v2)
	assert.NoError(s.T(), err)

	err = mt.AddLeaf(n2_)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "621b0f04a6486a2e9205ee837635daecd0feeb7409ad42f9a5f00cdf82c934a9", mt.Root().Hex())
	assert.Equal(s.T(), "76534138237239231515859035502772486263463178175980489503663557460094727691106", mt.Root().BigInt().Text(10))
}

func (s *MerkleTreeTestSuite) TestAddNode_Keccak256() {
	provider := &testSqlProvider{db: s.gormDB}
	hasher := &hash.Keccak256Hasher{}
	db := storage.NewSqlStorage(provider, "test_1", hasher)
	mt, err := NewMerkleTree(db, 64)
	assert.NoError(s.T(), err)

	x, _ := new(big.Int).SetString("9198063289874244593808956064764348354864043212453245695133881114917754098693", 10)
	y, _ := new(big.Int).SetString("3600411115173311692823743444460566395943576560299970643507632418781961416843", 10)
	alice := &babyjub.PublicKey{
		X: x,
		Y: y,
	}
	salt1, _ := new(big.Int).SetString("43c49e8ba68a9b8a6bb5c230a734d8271a83d2f63722e7651272ebeef5446e", 16)
	utxo1 := node.NewFungible(big.NewInt(10), alice, salt1, hasher)
	idx1, err := utxo1.CalculateIndex()
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "7760ce7c5a1b6b61e0647d46e52981efea01f53312d061ae7ad3c83d890e7843", idx1.BigInt().Text(16))

	n1, err := node.NewLeafNode(utxo1, nil)
	assert.NoError(s.T(), err)
	err = mt.AddLeaf(n1)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "a82f5e2badeb0e558f3e198f2ab1d55eb2134d90d7d886f901c70b859fa24f59", mt.Root().Hex())
	assert.Equal(s.T(), "40396546825579280798065248979086627653929672915398237421353407506268343381928", mt.Root().BigInt().Text(10))

	// adding a 2nd node to test the tree update and branch nodes
	salt2, _ := new(big.Int).SetString("19b965f7629e4f0c4bd0b8f9c87f17580f18a32a31b4641550071ee4916bbbfc", 16)
	utxo2 := node.NewFungible(big.NewInt(20), alice, salt2, hasher)
	idx2, err := utxo2.CalculateIndex()
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "1853944f79b4386d0b7a71243d19fb40a90484e0bc8a050b5f6b036a28fc221a", idx2.BigInt().Text(16))
	n2, err := node.NewLeafNode(utxo2, nil)
	assert.NoError(s.T(), err)
	err = mt.AddLeaf(n2)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "9de0daf77df872b087e07547e6d9a8ee87a4f35200638dc58ddbe7615c9a8e40", mt.Root().Hex())

	// adding a 3rd node to test the tree update and branch nodes with a left/right child node
	salt3, _ := new(big.Int).SetString("9b0b93df975547e430eabff085a77831b8fcb6b5396e6bb815fda8d14125370", 16)
	utxo3 := node.NewFungible(big.NewInt(30), alice, salt3, hasher)
	idx3, err := utxo3.CalculateIndex()
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "8e75e5af39d302122a2b48fa75f666843a9c46b3f0c720d3e503280f22947539", idx3.BigInt().Text(16))
	n3, err := node.NewLeafNode(utxo3, nil)
	assert.NoError(s.T(), err)
	err = mt.AddLeaf(n3)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "194b5df5301abc8a78c1beacf5c6517b33471da0b44a0acbcf54f12e969d9ec2", mt.Root().Hex())

	// adding a 4th node to test the tree update and branch nodes with the other left/right child node
	salt4, _ := new(big.Int).SetString("194ec10ec96a507c7c9b60df133d13679b874b0bd6ab89920135508f55b3f064", 16)
	utxo4 := node.NewFungible(big.NewInt(40), alice, salt4, hasher)
	idx4, err := utxo4.CalculateIndex()
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "f073e8fe1328a3b8047915a093ecbffba905d20960f43bddb85ec7eb73ea318b", idx4.BigInt().Text(16))
	n4, err := node.NewLeafNode(utxo4, nil)
	assert.NoError(s.T(), err)
	err = mt.AddLeaf(n4)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "31173b6eccce929ada2c71e408361502fc71981c8d04e1230d0ecf1888ad5949", mt.Root().Hex())

	// test storage persistence
	rawDB := mt.(*sparseMerkleTree).db
	rootIdx, err := rawDB.GetRootNodeRef()
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "31173b6eccce929ada2c71e408361502fc71981c8d04e1230d0ecf1888ad5949", rootIdx.Hex())
	dbNode1, err := rawDB.GetNode(n1.Ref())
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), n1.Index().Hex(), dbNode1.Index().Hex())

	// test storage persistence across tree creation
	mt2, err := NewMerkleTree(db, 10)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "31173b6eccce929ada2c71e408361502fc71981c8d04e1230d0ecf1888ad5949", mt2.Root().Hex())
}

func (s *MerkleTreeTestSuite) TestAddNodeWithValue() {
	provider := &testSqlProvider{db: s.gormDB}
	hasher := &hash.PoseidonHasher{}
	db := storage.NewSqlStorage(provider, "test_1", hasher)
	mt, err := NewMerkleTree(db, 64)
	assert.NoError(s.T(), err)

	num1, _ := new(big.Int).SetString("2096622280825605732680813932752245818650977932351778776082900098091126550803", 10)
	idx1, _ := node.NewNodeIndexFromBigInt(num1, hasher)
	i1 := utils.NewIndexOnly(idx1)
	value, _ := new(big.Int).SetString("103929005307130220006098923584552504982110632080", 10)
	node1, _ := node.NewLeafNode(i1, value)

	err = mt.AddLeaf(node1)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "30217116944257091399475853416903058458458941628960743326838300308858186421", mt.Root().BigInt().Text(10))

	num2, _ := new(big.Int).SetString("15090204826491664659381707037550246536226753383907517787209741376692915222845", 10)
	idx2, _ := node.NewNodeIndexFromBigInt(num2, hasher)
	i2 := utils.NewIndexOnly(idx2)
	value2, _ := new(big.Int).SetString("103929005307130220006098923584552504982110632080", 10)
	node2, _ := node.NewLeafNode(i2, value2)

	err = mt.AddLeaf(node2)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "13510168183919975355906555974433619775354581939566212907435695290053458902080", mt.Root().BigInt().Text(10))
}

func (s *MerkleTreeTestSuite) TestAddNodeWithValue_Keccak256() {
	provider := &testSqlProvider{db: s.gormDB}
	hasher := &hash.Keccak256Hasher{}
	db := storage.NewSqlStorage(provider, "test_1", hasher)
	mt, err := NewMerkleTree(db, 64)
	assert.NoError(s.T(), err)

	num1, _ := new(big.Int).SetString("2096622280825605732680813932752245818650977932351778776082900098091126550803", 10)
	idx1, _ := node.NewNodeIndexFromBigInt(num1, hasher)
	i1 := utils.NewIndexOnly(idx1)
	value, _ := new(big.Int).SetString("103929005307130220006098923584552504982110632080", 10)
	node1, _ := node.NewLeafNode(i1, value)

	err = mt.AddLeaf(node1)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "82804925767799109303590842121762391552430492588263699753375838529512360846329", mt.Root().BigInt().Text(10))

	num2, _ := new(big.Int).SetString("15090204826491664659381707037550246536226753383907517787209741376692915222845", 10)
	idx2, _ := node.NewNodeIndexFromBigInt(num2, hasher)
	i2 := utils.NewIndexOnly(idx2)
	value2, _ := new(big.Int).SetString("103929005307130220006098923584552504982110632080", 10)
	node2, _ := node.NewLeafNode(i2, value2)

	err = mt.AddLeaf(node2)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "89791312731002442049339692978860823183831246235876919306102714467446488917251", mt.Root().BigInt().Text(10))
}

func (s *MerkleTreeTestSuite) TestAddNodeFailExistingKey() {
	provider := &testSqlProvider{db: s.gormDB}
	hasher := &hash.PoseidonHasher{}
	db := storage.NewSqlStorage(provider, "test_1", hasher)
	mt, err := NewMerkleTree(db, 64)
	assert.NoError(s.T(), err)

	x, _ := new(big.Int).SetString("9198063289874244593808956064764348354864043212453245695133881114917754098693", 10)
	y, _ := new(big.Int).SetString("3600411115173311692823743444460566395943576560299970643507632418781961416843", 10)
	alice := &babyjub.PublicKey{
		X: x,
		Y: y,
	}
	salt1, _ := new(big.Int).SetString("43c49e8ba68a9b8a6bb5c230a734d8271a83d2f63722e7651272ebeef5446e", 16)
	utxo1 := node.NewFungible(big.NewInt(10), alice, salt1, hasher)
	idx1, err := utxo1.CalculateIndex()
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "11a22e32f5010d3658d1da9c93f26b77afe7a84346f49eae3d1d4fc6cd0a36fd", idx1.BigInt().Text(16))

	n1, err := node.NewLeafNode(utxo1, nil)
	assert.NoError(s.T(), err)
	err = mt.AddLeaf(n1)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "525b60b382630ee7825bea84fb8808c13ede1fb827fe683cd5b14d76f6ac6d0b", mt.Root().Hex())

	err = mt.AddLeaf(n1)
	assert.EqualError(s.T(), err, "key already exists")
}

func (s *MerkleTreeTestSuite) TestGenerateProof() {
	const levels = 64
	provider := &testSqlProvider{db: s.gormDB}
	hasher := &hash.PoseidonHasher{}
	db := storage.NewSqlStorage(provider, "test_1", hasher)
	mt, _ := NewMerkleTree(db, levels)

	alice := testutils.NewKeypair()
	utxo1 := node.NewFungible(big.NewInt(10), alice.PublicKey, big.NewInt(12345), hasher)
	node1, err := node.NewLeafNode(utxo1, nil)
	assert.NoError(s.T(), err)
	err = mt.AddLeaf(node1)
	assert.NoError(s.T(), err)

	utxo2 := node.NewFungible(big.NewInt(10), alice.PublicKey, big.NewInt(12346), hasher)
	node2, err := node.NewLeafNode(utxo2, nil)
	assert.NoError(s.T(), err)
	err = mt.AddLeaf(node2)
	assert.NoError(s.T(), err)

	target1 := node1.Index().BigInt()

	utxo3 := node.NewFungible(big.NewInt(10), alice.PublicKey, big.NewInt(12347), hasher)
	node3, err := node.NewLeafNode(utxo3, nil)
	assert.NoError(s.T(), err)
	target2 := node3.Index().BigInt()
	proofs, foundValues, err := mt.GenerateProofs([]*big.Int{target1, target2}, mt.Root())
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), target1, foundValues[0])
	assert.True(s.T(), proofs[0].(*proof).existence)
	valid := VerifyProof(mt.Root(), proofs[0], node1)
	assert.True(s.T(), valid)
	assert.False(s.T(), proofs[1].(*proof).existence)

	proof3, err := proofs[0].ToCircomVerifierProof(target1, foundValues[0], mt.Root(), levels)
	assert.NoError(s.T(), err)
	assert.False(s.T(), proof3.IsOld0)
}

func (s *MerkleTreeTestSuite) TestGenerateProofWithValue() {
	const levels = 64
	provider := &testSqlProvider{db: s.gormDB}
	hasher := &hash.PoseidonHasher{}
	db := storage.NewSqlStorage(provider, "test_1", hasher)
	mt, _ := NewMerkleTree(db, levels)

	x, _ := new(big.Int).SetString("5942093613500723806297813179240005997319949155197126751651583942828687054842", 10)
	y, _ := new(big.Int).SetString("2705857439293983766697920596184407125756255052151793307734211470588083660177", 10)
	alice := &babyjub.PublicKey{
		X: x,
		Y: y,
	}
	salt1, _ := new(big.Int).SetString("892402318960242780398177635659111260182315141240454518439802375724353727618", 10)

	value, _ := new(big.Int).SetString("103929005307130220006098923584552504982110632080", 10)

	utxo1 := node.NewFungible(big.NewInt(15), alice, salt1, hasher)
	node1, err := node.NewLeafNode(utxo1, value)
	assert.NoError(s.T(), err)
	err = mt.AddLeaf(node1)
	assert.NoError(s.T(), err)

	salt2, _ := new(big.Int).SetString("20958393090813127612863788731259135207417921338630643176495259330913242296380", 10)
	utxo2 := node.NewFungible(big.NewInt(100), alice, salt2, hasher)
	node2, err := node.NewLeafNode(utxo2, value)
	assert.NoError(s.T(), err)
	err = mt.AddLeaf(node2)
	assert.NoError(s.T(), err)

	target1 := node1.Index().BigInt()
	target2 := node2.Index().BigInt()

	proofs, foundValues, err := mt.GenerateProofs([]*big.Int{target1, target2}, mt.Root())
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), value, foundValues[0])
	assert.True(s.T(), proofs[0].(*proof).existence)
	valid := VerifyProof(mt.Root(), proofs[0], node1)
	assert.True(s.T(), valid)
	assert.Equal(s.T(), value, foundValues[1])
	assert.True(s.T(), proofs[1].(*proof).existence)
	valid = VerifyProof(mt.Root(), proofs[1], node2)
	assert.True(s.T(), valid)

	proof3, err := proofs[0].ToCircomVerifierProof(target1, foundValues[0], mt.Root(), levels)
	assert.NoError(s.T(), err)
	assert.False(s.T(), proof3.IsOld0)
}

func (s *MerkleTreeTestSuite) TestVerifyProof() {
	const levels = 100
	provider := &testSqlProvider{db: s.gormDB}
	hasher := &hash.PoseidonHasher{}
	db := storage.NewSqlStorage(provider, "test_1", hasher)
	mt, _ := NewMerkleTree(db, levels)

	alice := testutils.NewKeypair()
	values := []int{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
	done := make(chan bool, len(values))
	startProving := make(chan core.Node, len(values))
	for idx, value := range values {
		go func(v int, idx int) {
			salt := rand.Intn(100000)
			utxo := node.NewFungible(big.NewInt(int64(v)), alice.PublicKey, big.NewInt(int64(salt)), hasher)
			node, err := node.NewLeafNode(utxo, nil)
			assert.NoError(s.T(), err)
			err = mt.AddLeaf(node)
			assert.NoError(s.T(), err)
			startProving <- node
			done <- true
		}(value, idx)
	}

	go func() {
		// trigger the proving process after 1 nodes are added
		n := <-startProving
		fmt.Println("Received node for proving")

		target := n.Index().BigInt()
		root := mt.Root()
		p, _, err := mt.GenerateProofs([]*big.Int{target}, root)
		assert.NoError(s.T(), err)
		assert.True(s.T(), p[0].(*proof).existence)

		valid := VerifyProof(root, p[0], n)
		assert.True(s.T(), valid)
	}()

	for i := 0; i < len(values); i++ {
		<-done
	}

	fmt.Println("All done")
}

func (s *MerkleTreeTestSuite) TestSqliteStorage() {
	provider := &testSqlProvider{db: s.gormDB}
	hasher := &hash.PoseidonHasher{}
	db := storage.NewSqlStorage(provider, "test_1", hasher)
	mt, err := NewMerkleTree(db, 64)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), mt)

	tokenId := big.NewInt(1001)
	uriString := "https://example.com/token/1001"
	assert.NoError(s.T(), err)
	sender := testutils.NewKeypair()
	salt1 := crypto.NewSalt()

	utxo1 := node.NewNonFungible(tokenId, uriString, sender.PublicKey, salt1, hasher)
	n1, err := node.NewLeafNode(utxo1, nil)
	assert.NoError(s.T(), err)
	err = mt.AddLeaf(n1)
	assert.NoError(s.T(), err)

	dbNode := core.SMTNode{RefKey: n1.Ref().Hex()}
	err = s.gormDB.Table(core.NodesTablePrefix + "test_1").First(&dbNode).Error
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), n1.Ref().Hex(), dbNode.RefKey)
}

func TestMerkleTreeSuite(t *testing.T) {
	suite.Run(t, new(MerkleTreeTestSuite))
}
