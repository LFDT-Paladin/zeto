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

package node

import (
	"errors"
	"math/big"
	"testing"

	"github.com/hyperledger-labs/zeto/go-sdk/internal/crypto/hash"
	"github.com/hyperledger-labs/zeto/go-sdk/internal/sparse-merkle-tree/utils"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/sparse-merkle-tree/core"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/assert"
)

func TestNodeIndex(t *testing.T) {
	idx0, _ := NewNodeIndexFromBigInt(big.NewInt(0), &hash.PoseidonHasher{})
	assert.Equal(t, "0000000000000000000000000000000000000000000000000000000000000000", idx0.Hex())
	idx1, _ := NewNodeIndexFromBigInt(big.NewInt(1), &hash.PoseidonHasher{})
	assert.Equal(t, "0100000000000000000000000000000000000000000000000000000000000000", idx1.Hex())
	idx2, _ := NewNodeIndexFromBigInt(big.NewInt(10), &hash.PoseidonHasher{})
	assert.Equal(t, "0a00000000000000000000000000000000000000000000000000000000000000", idx2.Hex())

	idx3, _ := NewNodeIndexFromBigInt(big.NewInt(12345678), &hash.PoseidonHasher{})
	assert.Equal(t, "4e61bc0000000000000000000000000000000000000000000000000000000000", idx3.Hex())

	v4, _ := new(big.Int).SetString("4932297968297298434239270129193057052722409868268166443802652458940273154854", 10)
	idx4, _ := NewNodeIndexFromBigInt(v4, &hash.PoseidonHasher{})
	assert.Equal(t, "265baaf161e875c372d08e50f52abddc01d32efc93e90290bb8b3d9ceb94e70a", idx4.Hex())
	expectedBytes4 := []byte{38, 91, 170, 241, 97, 232, 117, 195, 114, 208, 142, 80, 245, 42, 189, 220, 1, 211, 46, 252, 147, 233, 2, 144, 187, 139, 61, 156, 235, 148, 231, 10}
	rawIndex4 := idx4.(*nodeIndex)
	assert.Equal(t, expectedBytes4, rawIndex4[:])

	idx5, err := NewNodeIndexFromHex("265baaf161e875c372d08e50f52abddc01d32efc93e90290bb8b3d9ceb94e70a")
	assert.NoError(t, err)
	assert.Equal(t, 0, v4.Cmp(idx5.BigInt()))
}

func TestNewEmptyNode(t *testing.T) {
	node := NewEmptyNode()
	assert.Equal(t, node.Type(), core.NodeTypeEmpty)
	assert.Nil(t, node.Index())
	assert.Nil(t, node.Ref())
	assert.Nil(t, node.LeftChild())
	assert.Nil(t, node.RightChild())
}

func TestNewLeafNode(t *testing.T) {
	idx, _ := NewNodeIndexFromBigInt(big.NewInt(10), &hash.PoseidonHasher{})
	i := utils.NewIndexOnly(idx)
	node, err := NewLeafNode(i, nil, &hash.PoseidonHasher{})
	assert.NoError(t, err)
	assert.Equal(t, node.Type(), core.NodeTypeLeaf)
	assert.Equal(t, node.Index(), idx)
	elements := []*big.Int{idx.BigInt(), idx.BigInt(), big.NewInt(1)}
	hash, err := poseidon.Hash(elements)
	assert.NoError(t, err)
	assert.Equal(t, node.Ref().BigInt(), hash)
	assert.Nil(t, node.LeftChild())
	assert.Nil(t, node.RightChild())
}

func TestNewLeafNodeKeccak256(t *testing.T) {
	idx, _ := NewNodeIndexFromBigInt(big.NewInt(10), &hash.PoseidonHasher{})
	i := utils.NewIndexOnly(idx)
	node, err := NewLeafNode(i, nil, &hash.Keccak256Hasher{})
	assert.NoError(t, err)
	assert.Equal(t, node.Type(), core.NodeTypeLeaf)
	assert.Equal(t, node.Index(), idx)
	elements := []*big.Int{idx.BigInt(), idx.BigInt(), big.NewInt(1)}
	hash, err := (&hash.Keccak256Hasher{}).Hash(elements)
	assert.NoError(t, err)
	assert.Equal(t, node.Ref().BigInt(), hash)
	assert.Nil(t, node.LeftChild())
	assert.Nil(t, node.RightChild())
}

func TestNewLeafNodeWithValue(t *testing.T) {
	idx, _ := NewNodeIndexFromBigInt(big.NewInt(10), &hash.PoseidonHasher{})
	i := utils.NewIndexOnly(idx)
	node, err := NewLeafNode(i, big.NewInt(12345), &hash.PoseidonHasher{})
	assert.NoError(t, err)
	assert.Equal(t, node.Type(), core.NodeTypeLeaf)
	assert.Equal(t, node.Index(), idx)
	elements := []*big.Int{idx.BigInt(), big.NewInt(12345), big.NewInt(1)}
	hash, err := poseidon.Hash(elements)
	assert.NoError(t, err)
	assert.Equal(t, node.Ref().BigInt(), hash)
	assert.Nil(t, node.LeftChild())
	assert.Nil(t, node.RightChild())
}

func TestNewBranchNode(t *testing.T) {
	idx0, _ := NewNodeIndexFromBigInt(big.NewInt(0), &hash.PoseidonHasher{})
	idx1, _ := NewNodeIndexFromBigInt(big.NewInt(1), &hash.PoseidonHasher{})
	node, err := NewBranchNode(idx0, idx1, &hash.PoseidonHasher{})
	assert.NoError(t, err)
	assert.Equal(t, node.Type(), core.NodeTypeBranch)
	assert.Nil(t, node.Index())
	elements := []*big.Int{idx0.BigInt(), idx1.BigInt()}
	hash, err := poseidon.Hash(elements)
	assert.NoError(t, err)
	assert.Equal(t, node.Ref().BigInt(), hash)
	assert.Equal(t, node.LeftChild(), idx0)
	assert.Equal(t, node.RightChild(), idx1)
}

type badIndex struct{}

func (f *badIndex) CalculateIndex() (core.NodeIndex, error) {
	return nil, errors.New("Bang!")
}

func TestNewLeafNodeFail(t *testing.T) {
	_, err := NewLeafNode(&badIndex{}, nil, &hash.PoseidonHasher{})
	assert.EqualError(t, err, "Bang!")
}
