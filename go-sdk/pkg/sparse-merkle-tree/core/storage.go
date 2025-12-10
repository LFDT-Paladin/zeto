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
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/utxo/core"
	"gorm.io/gorm"
)

type Storage interface {
	// GetRootNodeRef returns the root node index.
	// Must return an ErrNotFound error if it does not exist.
	GetRootNodeRef() (NodeRef, error)
	// UpsertRootNodeIndex updates the root node index.
	UpsertRootNodeRef(NodeRef) error
	// GetNode returns the node with the given reference hash
	// Must return an ErrNotFound error if it does not exist.
	GetNode(NodeRef) (Node, error)
	// InsertNode inserts a node into the storage. Where the private values of a node are stored
	// is implementation-specific
	InsertNode(Node) error
	// BeginTx executes a batch of operations in a single transaction. The semantics of the batch
	// function follows the semantics of the gorm.DB.Transaction function.
	BeginTx() (Transaction, error)
	// Close closes the storage resource
	Close()
	// GetHasher returns the hasher used by the storage
	GetHasher() core.Hasher
}

type Transaction interface {
	UpsertRootNodeRef(NodeRef) error
	GetNode(NodeRef) (Node, error)
	InsertNode(Node) error
	Commit() error
	Rollback() error
}

const (
	// we use a table to store the root node indexes for
	// all the merkle trees in the database
	TreeRootsTable = "merkelTreeRoots"
	// we use a separate table to store the nodes of each
	// sparse merkle tree by using the following name as
	// the prefix, followed by the name of the tree
	NodesTablePrefix = "smtNodes_"
)

// SqlDBProvider is the interface for providing access to a SQL database to
// the storage layer implementations that are backed by a SQL database.
type SqlDBProvider interface {
	DB() *gorm.DB
	Close()
}

// SMTRoot is used to persist tree root in SQL databases via gorm
type SMTRoot struct {
	// the name of the merkle tree
	Name string `gorm:"primaryKey"`
	// this must be the hex bytes of the root reference hash
	// following the big-endian encoding
	RootRef string `gorm:"size:64"`
}

// SMTNode is the structure of a node in the merkle tree.
// It only captures the reference key and the index of the node.
// The value properties of a node are local states that are
// handled outside of the merkle tree library.
type SMTNode struct {
	RefKey     string `gorm:"primaryKey;size:64"`
	Type       byte
	Index      *string `gorm:"size:64"` // only leaf nodes have an index
	Value      *string `gorm:"size:64"` // only leaf nodes have a value
	LeftChild  *string `gorm:"size:64"` // only branch nodes have children
	RightChild *string `gorm:"size:64"`
}
