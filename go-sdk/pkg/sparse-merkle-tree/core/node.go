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

package core

import (
	"math/big"

	"github.com/hyperledger-labs/zeto/go-sdk/pkg/utxo/core"
)

type NodeType int

const (
	// in a sparse merkle tree, all nodes at every possible index are considered
	// present, but nodes are empty until a value has been set to that index.
	// The NodeTypeEmpty is used to represent a non-existent value at an index.
	NodeTypeEmpty NodeType = iota
	// NodeTypeBranch is a node that has two children, which are the left and right
	NodeTypeBranch
	// NodeTypeLeaf is a node that has a value object, and is the bottom level
	// of the tree (which has the highest level number)
	NodeTypeLeaf
)

// NodeRef defines functions associated with the reference hash of SMT nodes, this interface applies to all types of nodes (reference hash calculated differently depending on node type)
type NodeRef interface {
	// BigInt returns the big integer representation of the reference hash
	BigInt() *big.Int
	// Hex returns the hex string representation of the reference hash in big-endian format
	Hex() string
	// IsZero returns true if the reference hash is zero
	IsZero() bool
	// Equal returns true if two reference hashes equal to each other
	Equal(NodeRef) bool
	// GetHasher returns the hasher used to compute the node reference
	GetHasher() core.Hasher
}

// NodeIndex defines the functions of leaf nodes in the SMT, which provide access to their node paths in addition to the NodeRef functions.
type NodeIndex interface {
	NodeRef
	// IsBitOne returns true if the index bit at the given position is 1
	IsBitOne(uint) bool
	// ToPath returns the binary path from the root to the leaf
	ToPath(int) []bool
}

// Indexable is the interface that wraps the internal state object of a
// Node, which is used to produce a unique index for the node.
type Indexable interface {
	CalculateIndex() (NodeIndex, error)
	GetHasher() core.Hasher
}

// Node is the object of a node in the Sparse Merkle Tree, which has an
// index, and a value object. The node can be a leaf (sits on the bottom
// of the tree), a branch (on the upper levels of the tree), or empty.
type Node interface {
	// returns the type of the node
	Type() NodeType
	// calculate the index from the values of a leaf node, which determines
	// the position of the leaf node in the bottom level of the tree
	Index() NodeIndex
	// calculate the index from the values of a leaf node, which determines
	// the position of the leaf node in the bottom level of the tree
	Value() *big.Int
	// calculated by combining the index and value of the node, as
	// the reference to the node from its parent in the tree, as well as the
	// key to the storage record for the node
	Ref() NodeRef
	// returns the index of the left child. Only branch nodes have a left child.
	LeftChild() NodeRef
	// returns the index of the right child. Only branch nodes have a right child.
	RightChild() NodeRef
}

func (t NodeType) ToByte() byte {
	switch t {
	case NodeTypeEmpty:
		return 0
	case NodeTypeBranch:
		return 1
	case NodeTypeLeaf:
		return 2
	default:
		return 3
	}
}

func NodeTypeFromByte(b byte) NodeType {
	switch b {
	case 0:
		return NodeTypeEmpty
	case 1:
		return NodeTypeBranch
	case 2:
		return NodeTypeLeaf
	default:
		return NodeTypeEmpty
	}
}
