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
	"encoding/hex"
	"math/big"
	"strings"

	"github.com/hyperledger-labs/zeto/go-sdk/internal/crypto/hash"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/sparse-merkle-tree/core"
	apicore "github.com/hyperledger-labs/zeto/go-sdk/pkg/utxo/core"
)

const INDEX_BYTES_LEN = 32

var ZERO_INDEX, _ = NewNodeIndexFromBigInt(big.NewInt(0), &hash.PoseidonHasher{})

// nodeIndex is a wrapper around []byte to implement the NodeIndex interface.
// it's a 256-bit number. the path from the root node to a leaf node is determined
// by the index's bits. 0 means go left, 1 means go right.
type nodeIndex struct {
	index  [32]byte
	hasher apicore.Hasher
}

// node is an implementation of the Node interface
type node struct {
	nodeType   core.NodeType
	i          core.NodeIndex // the index of the node
	v          *big.Int       // the value of the node
	refKey     core.NodeRef
	state      core.Indexable // private states to be hashed into the index
	leftChild  core.NodeRef
	rightChild core.NodeRef
}

// //////////////////////////////////////
// implementation of node
func NewEmptyNode() core.Node {
	return &node{nodeType: core.NodeTypeEmpty}
}

// the value parameter is optional. if "nil", the index hash is used in the
// place of the value when calculating the node reference hash (aka "node key").
func NewLeafNode(s core.Indexable, v *big.Int) (core.Node, error) {
	n := &node{nodeType: core.NodeTypeLeaf, state: s}
	idx, err := n.state.CalculateIndex()
	if err != nil {
		return nil, err
	}
	n.i = idx
	n.v = v

	// the leaf node's reference is calculated as follows:
	// 1. get the node's index, call it hKey
	// 2. calculate the hash of the value object, call it hValue. if no value is provided, use hKey
	// 2. calculate hash(hKey, hValue, 1)
	hKey := n.i.BigInt()
	hValue := n.v
	if hValue == nil {
		hValue = hKey
	}
	elements := []*big.Int{hKey, hValue, big.NewInt(1)}
	hash, err := s.GetHasher().Hash(elements)
	if err != nil {
		return nil, err
	}
	n.refKey, err = NewNodeIndexFromBigInt(hash, s.GetHasher())
	return n, err
}

func NewBranchNode(leftChild, rightChild core.NodeRef, hasher apicore.Hasher) (core.Node, error) {
	n := &node{nodeType: core.NodeTypeBranch, leftChild: leftChild, rightChild: rightChild}
	elements := []*big.Int{leftChild.BigInt(), rightChild.BigInt()}
	hash, err := hasher.Hash(elements)
	if err != nil {
		return nil, err
	}
	n.refKey, err = NewNodeIndexFromBigInt(hash, hasher)
	return n, err
}

func (n *node) Type() core.NodeType {
	return n.nodeType
}

func (n *node) Index() core.NodeIndex {
	return n.i
}

func (n *node) Ref() core.NodeRef {
	return n.refKey
}

func (n *node) Value() *big.Int {
	return n.v
}

func (n *node) LeftChild() core.NodeRef {
	return n.leftChild
}

func (n *node) RightChild() core.NodeRef {
	return n.rightChild
}

// //////////////////////////////////////
// implementation of nodeIndex
func NewNodeIndexFromBigInt(i *big.Int, hasher apicore.Hasher) (core.NodeIndex, error) {
	// verfy that the integer are valid and fit inside the Finite Field.
	if !hasher.CheckInRange(i) {
		return nil, ErrNodeIndexTooLarge
	}
	idx := &nodeIndex{hasher: hasher}
	copy(idx.index[:], swapEndianness(i.Bytes()))
	return idx, nil
}

// NewNodeIndexFromHex creates a new NodeIndex from a hex string that
// represents the index in big-endian format.
func NewNodeIndexFromHex(h string, hasher apicore.Hasher) (core.NodeIndex, error) {
	h = strings.TrimPrefix(h, "0x")
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	if len(b) != INDEX_BYTES_LEN {
		return nil, ErrNodeBytesBadSize
	}
	idx := &nodeIndex{hasher: hasher}
	copy(idx.index[:], b)
	return idx, nil
}

func (idx *nodeIndex) BigInt() *big.Int {
	return new(big.Int).SetBytes(swapEndianness(idx.index[:]))
}

func (idx *nodeIndex) Hex() string {
	return hex.EncodeToString(idx.index[:])
}

func (idx *nodeIndex) IsZero() bool {
	return idx.BigInt().Sign() == 0
}

func (idx *nodeIndex) Equal(other core.NodeRef) bool {
	return idx.BigInt().Cmp(other.BigInt()) == 0
}

func (idx *nodeIndex) GetHasher() apicore.Hasher {
	return idx.hasher
}

// getPath returns the binary path, from the root to the leaf.
func (idx *nodeIndex) ToPath(levels int) []bool {
	path := make([]bool, levels)
	for l := 0; l < levels; l++ {
		path[l] = idx.IsBitOne(uint(l))
	}
	return path
}

func (idx *nodeIndex) IsBitOne(pos uint) bool {
	if pos >= 256 {
		return false
	}
	return (idx.index[pos/8] & (1 << (pos % 8))) != 0
}

// swapEndianness swaps the order of the bytes in the byte array of a node index.
// the byte array is used in little-endian format for calculating the big integer value of the index,
// while the big-endian format is used as the bit-wise path to traverse down the tree.
func swapEndianness(b []byte) []byte {
	o := make([]byte, len(b))
	for i := range b {
		o[len(b)-1-i] = b[i]
	}
	return o
}
