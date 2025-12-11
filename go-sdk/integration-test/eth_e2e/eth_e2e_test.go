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
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	itestcommon "github.com/hyperledger-labs/zeto/go-sdk/integration-test/common"
	"github.com/hyperledger-labs/zeto/go-sdk/internal/sparse-merkle-tree/smt"
	"github.com/hyperledger-labs/zeto/go-sdk/internal/testutils"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func (s *EthE2ETestSuite) SetupSuite() {
	logrus.SetLevel(logrus.DebugLevel)
	s.dbfile, s.db, s.gormDB, _ = itestcommon.NewSqliteStorage(s.T())

	// Initialize Ethereum client from environment variable
	s.rpcURL = os.Getenv("ETH_RPC_URL")
	if s.rpcURL == "" {
		s.rpcURL = "http://localhost:8545" // Default to localhost
	}

	// Load Zeto contract address from environment variable
	zetoContractAddressStr := os.Getenv("ZETO_CONTRACT_ADDRESS")
	if zetoContractAddressStr == "" {
		s.T().Skip("Zeto contract address not set. Set ZETO_CONTRACT_ADDRESS environment variable.")
		return
	} else {
		s.zetoContractAddress = common.HexToAddress(zetoContractAddressStr)
	}

	s.zetoContractName = os.Getenv("ZETO_CONTRACT_NAME")
	require.NotEmpty(s.T(), s.zetoContractName)
	s.T().Logf("%s contract address loaded: %s", s.zetoContractName, s.zetoContractAddress.Hex())

	// Contract binding will be created after ABI is loaded

	// Generate or load ECDSA private key for Ethereum transactions
	// For testing, we'll use a well-known private key that corresponds to the sender address
	// In production, you would load this from a secure keystore
	ethPrivateKeyStr := os.Getenv("ETH_PRIVATE_KEY")
	if ethPrivateKeyStr == "" {
		// Use a well-known test private key (corresponds to 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266)
		ethPrivateKeyStr = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
		s.T().Logf("ETH_PRIVATE_KEY environment variable not set. Using test private key.")
	}

	ethPrivateKey, err := crypto.HexToECDSA(ethPrivateKeyStr[2:]) // Remove 0x prefix
	if err != nil {
		s.T().Logf("Failed to parse ECDSA private key: %v", err)
	} else {
		s.deployerPrivateKey = ethPrivateKey
		s.T().Logf("ECDSA private key loaded successfully")
	}
	// calculate the sender's address based on the private key
	senderAddress := crypto.PubkeyToAddress(ethPrivateKey.PublicKey)
	s.senderAddress = senderAddress
	s.T().Logf("Sender address: %s", senderAddress.Hex())

	// Connect to Ethereum client
	client, err := ethclient.Dial(s.rpcURL)
	if err != nil {
		s.T().Logf("Warning: Failed to connect to Ethereum client at %s: %v", s.rpcURL, err)
		s.T().Logf("Ethereum-related tests will be skipped. Set ETH_RPC_URL environment variable to enable.")
	} else {
		s.ethClient = client
		s.T().Logf("Connected to Ethereum client at %s", s.rpcURL)
	}

	// Load the Zeto_Anon contract artifact
	var artifactPath string
	switch s.zetoContractName {
	case "Zeto_Anon":
		artifactPath = filepath.Join("..", "..", "..", "solidity", "artifacts", "contracts", "zeto_anon.sol", "Zeto_Anon.json")
	case "Zeto_AnonNullifierQurrency":
		artifactPath = filepath.Join("..", "..", "..", "solidity", "artifacts", "contracts", "zeto_anon_nullifier_qurrency.sol", "Zeto_AnonNullifierQurrency.json")
	case "Zeto_AnonNullifier":
		artifactPath = filepath.Join("..", "..", "..", "solidity", "artifacts", "contracts", "zeto_anon_nullifier.sol", "Zeto_AnonNullifier.json")
	default:
		s.T().Skipf("Invalid Zeto contract name: %s", s.zetoContractName)
		return
	}

	artifact, err := loadContractArtifact(artifactPath)
	if err != nil {
		s.T().Skipf("Failed to load contract artifact: %v. Make sure to compile contracts first.", err)
		return
	}
	s.zetoContractABI = artifact.ABI

	// Create contract binding after ABI is loaded
	s.contract = bind.NewBoundContract(s.zetoContractAddress, s.zetoContractABI, s.ethClient, s.ethClient, s.ethClient)
	assert.NotNil(s.T(), s.contract)
	s.T().Logf("Contract binding created successfully")

	// setup the tokens and signals
	s.setupTokensAndSignals()
}

func (s *EthE2ETestSuite) TearDownSuite() {
	// Close Ethereum client if it was initialized
	if s.ethClient != nil {
		s.ethClient.Close()
	}

	err := os.Remove(s.dbfile.Name())
	assert.NoError(s.T(), err)
}

func (s *EthE2ETestSuite) setupTokensAndSignals() {
	// generate test key pairs for the BJJ keys
	sender := testutils.NewKeypair()
	receiver := testutils.NewKeypair()
	s.sender = sender
	s.receiver = receiver

	// setup the number of runs from the environment variable
	numRunsStr := os.Getenv("NUM_RUNS")
	if numRunsStr != "" {
		numRuns, err := strconv.Atoi(numRunsStr)
		assert.NoError(s.T(), err)
		s.numRuns = numRuns
	} else {
		s.numRuns = 10
	}

	// initialize latency tracking slices
	s.witnessTimes = make([]time.Duration, 0, s.numRuns)
	s.provingTimes = make([]time.Duration, 0, s.numRuns)
	s.txTimes = make([]time.Duration, 0, s.numRuns)
	s.txGasCosts = make([]uint64, 0, s.numRuns)

	// setup the signals for the regular circuits with 2 inputs and 2 outputs
	s.regularTests = make([]*itestcommon.Signals, s.numRuns)
	for i := 0; i < s.numRuns; i++ {
		s.regularTests[i] = itestcommon.NewSignals(s.sender, s.receiver, false, s.db, s.T())
	}

	// prepare the merkle proofs for the regular tests
	mt, err := smt.NewMerkleTree(s.db, itestcommon.MAX_HEIGHT)
	assert.NoError(s.T(), err)

	for i := 0; i < s.numRuns; i++ {
		// in the test we mint the input commitments for each test iteration on demand.
		for _, commitment := range s.regularTests[i].InputCommitments {
			itestcommon.AddCommitmentToMerkleTree(mt, commitment, s.T())
		}

		// in addition, the output commitments from the previous iteration will have been added to the SMT.
		if i > 0 {
			for _, commitment := range s.regularTests[i-1].OutputCommitments {
				itestcommon.AddCommitmentToMerkleTree(mt, commitment, s.T())
			}
		}
		s.regularTests[i].MerkleProofs, s.regularTests[i].Enabled, s.regularTests[i].Root = itestcommon.BuildMerkleProofs(s.regularTests[i].InputCommitments, s.db, s.T())
	}

	// setup the signals for the batch circuits with 10 inputs and 10 outputs
	s.batchTests = make([]*itestcommon.Signals, s.numRuns)
	for i := 0; i < s.numRuns; i++ {
		s.batchTests[i] = itestcommon.NewSignals(s.sender, s.receiver, true, s.db, s.T())
		// TODO: complete the batch test signals when we have batch tests
	}
}

// loadContractArtifact loads a contract artifact from a JSON file
func loadContractArtifact(artifactPath string) (*ContractArtifact, error) {
	data, err := os.ReadFile(artifactPath)
	if err != nil {
		return nil, err
	}

	var artifact ContractArtifact
	err = json.Unmarshal(data, &artifact)
	if err != nil {
		return nil, err
	}

	return &artifact, nil
}

// waitForTransactionReceipt waits for a transaction to be mined and returns its receipt
func (s *EthE2ETestSuite) waitForTransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			receipt, err := s.ethClient.TransactionReceipt(ctx, txHash)
			if err == ethereum.NotFound {
				continue // Transaction not yet mined
			}
			if err != nil {
				return nil, err
			}
			return receipt, nil
		}
	}
}

// calculateAndDisplayAverages calculates and displays average latencies across all runs
func (s *EthE2ETestSuite) calculateAndDisplayAverages() {
	if len(s.provingTimes) == 0 {
		s.T().Logf("No latency data to calculate averages")
		return
	}

	// Calculate averages
	var totalWitness, totalPrep, totalMining, totalLatency time.Duration
	var minWitness, maxWitness, minPrep, maxPrep, minMining, maxMining, minTotal, maxTotal time.Duration
	var totalGasCost uint64
	var minGasCost, maxGasCost uint64

	// Initialize min/max with first values
	minWitness = s.witnessTimes[0]
	maxWitness = s.witnessTimes[0]
	minPrep = s.provingTimes[0]
	maxPrep = s.provingTimes[0]
	minMining = s.txTimes[0]
	maxMining = s.txTimes[0]
	minTotal = s.witnessTimes[0] + s.provingTimes[0] + s.txTimes[0]
	maxTotal = s.witnessTimes[0] + s.provingTimes[0] + s.txTimes[0]
	minGasCost = s.txGasCosts[0]
	maxGasCost = s.txGasCosts[0]

	for i := 0; i < len(s.provingTimes); i++ {
		// Sum for averages
		totalWitness += s.witnessTimes[i]
		totalPrep += s.provingTimes[i]
		totalMining += s.txTimes[i]
		totalLatency += s.witnessTimes[i] + s.provingTimes[i] + s.txTimes[i]
		totalGasCost += s.txGasCosts[i]

		// Update min/max for witness time
		if s.witnessTimes[i] < minWitness {
			minWitness = s.witnessTimes[i]
		}
		if s.witnessTimes[i] > maxWitness {
			maxWitness = s.witnessTimes[i]
		}

		// Update min/max for preparation time
		if s.provingTimes[i] < minPrep {
			minPrep = s.provingTimes[i]
		}
		if s.provingTimes[i] > maxPrep {
			maxPrep = s.provingTimes[i]
		}

		// Update min/max for mining time
		if s.txTimes[i] < minMining {
			minMining = s.txTimes[i]
		}
		if s.txTimes[i] > maxMining {
			maxMining = s.txTimes[i]
		}

		// Update min/max for total latency
		if s.witnessTimes[i]+s.provingTimes[i]+s.txTimes[i] < minTotal {
			minTotal = s.witnessTimes[i] + s.provingTimes[i] + s.txTimes[i]
		}
		if s.witnessTimes[i]+s.provingTimes[i]+s.txTimes[i] > maxTotal {
			maxTotal = s.witnessTimes[i] + s.provingTimes[i] + s.txTimes[i]
		}

		// Update min/max for gas cost
		if s.txGasCosts[i] < minGasCost {
			minGasCost = s.txGasCosts[i]
		}
		if s.txGasCosts[i] > maxGasCost {
			maxGasCost = s.txGasCosts[i]
		}
	}

	// Calculate averages
	numRuns := len(s.provingTimes)
	avgWitness := totalWitness / time.Duration(numRuns)
	avgPrep := totalPrep / time.Duration(numRuns)
	avgMining := totalMining / time.Duration(numRuns)
	avgTotal := totalLatency / time.Duration(numRuns)
	avgGasCost := totalGasCost / uint64(numRuns)

	// Display results
	fmt.Printf("\n")
	fmt.Printf("=== Performance STATISTICS (%d runs) ===\n", numRuns)
	fmt.Printf("\n")
	fmt.Printf("Witness Generation Time:\n")
	fmt.Printf("  Average: %v\n", avgWitness)
	fmt.Printf("  Min:     %v\n", minWitness)
	fmt.Printf("  Max:     %v\n", maxWitness)
	fmt.Printf("\n")
	fmt.Printf("Proving Time:\n")
	fmt.Printf("  Average: %v\n", avgPrep)
	fmt.Printf("  Min:     %v\n", minPrep)
	fmt.Printf("  Max:     %v\n", maxPrep)
	fmt.Printf("\n")
	fmt.Printf("Transaction Time:\n")
	fmt.Printf("  Average: %v\n", avgMining)
	fmt.Printf("  Min:     %v\n", minMining)
	fmt.Printf("  Max:     %v\n", maxMining)
	fmt.Printf("\n")
	fmt.Printf("Total Transaction Latency:\n")
	fmt.Printf("  Average: %v\n", avgTotal)
	fmt.Printf("  Min:     %v\n", minTotal)
	fmt.Printf("  Max:     %v\n", maxTotal)
	fmt.Printf("\n")
	fmt.Printf("Transaction Gas Cost:\n")
	fmt.Printf("  Average: %v\n", avgGasCost)
	fmt.Printf("  Min:     %v\n", minGasCost)
	fmt.Printf("  Max:     %v\n", maxGasCost)
	fmt.Printf("\n")
	fmt.Printf("=== END Performance STATISTICS ===\n\n")
}

func TestEthE2ETestSuite(t *testing.T) {
	suite.Run(t, new(EthE2ETestSuite))
}
