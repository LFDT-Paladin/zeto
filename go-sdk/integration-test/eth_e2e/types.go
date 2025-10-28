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

package eth_e2e

import (
	"crypto/ecdsa"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	itestcommon "github.com/hyperledger-labs/zeto/go-sdk/integration-test/common"
	"github.com/hyperledger-labs/zeto/go-sdk/internal/testutils"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/sparse-merkle-tree/core"
	"github.com/stretchr/testify/suite"
	"gorm.io/gorm"
)

// ContractArtifact represents the structure of a Solidity contract artifact
type ContractArtifact struct {
	ABI      abi.ABI `json:"abi"`
	Bytecode string  `json:"bytecode"`
}

type EthE2ETestSuite struct {
	suite.Suite
	db     core.Storage
	dbfile *os.File
	gormDB *gorm.DB

	// Ethereum client for JSON RPC communication
	ethClient *ethclient.Client
	rpcURL    string

	// ECDSA private key for Ethereum transactions
	deployerPrivateKey *ecdsa.PrivateKey

	sender        *testutils.User
	senderAddress common.Address
	receiver      *testutils.User

	// Zeto contract address from environment variable
	zetoContractAddress common.Address
	zetoContractName    string
	zetoContractABI     abi.ABI
	contract            *bind.BoundContract

	regularTests []*itestcommon.Signals
	batchTests   []*itestcommon.Signals

	// how many runs
	numRuns int

	// latency tracking
	witnessTimes []time.Duration // time to generate the witness
	provingTimes []time.Duration // time to generate the proof
	txTimes      []time.Duration // time to send and mine the transaction
	txGasCosts   []uint64        // gas cost of the transaction
}
