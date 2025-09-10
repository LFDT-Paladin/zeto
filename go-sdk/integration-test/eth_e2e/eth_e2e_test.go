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
	"crypto/ecdsa"
	"encoding/json"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	itestcommon "github.com/hyperledger-labs/zeto/go-sdk/integration-test/common"
	"github.com/hyperledger-labs/zeto/go-sdk/internal/testutils"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/sparse-merkle-tree/core"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/util"
	"github.com/iden3/go-rapidsnark/prover"
	zktypes "github.com/iden3/go-rapidsnark/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
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

	sender          *testutils.User
	senderAddress   common.Address
	receiver        *testutils.User
	receiverAddress common.Address

	// Zeto contract address from environment variable
	zetoContractAddress common.Address
	zetoContractABI     abi.ABI
	contract            *bind.BoundContract

	regularTests []*itestcommon.Signals
	batchTests   []*itestcommon.Signals

	// how many runs
	numRuns int

	// latency tracking
	provingTimes   []time.Duration
	miningTimes    []time.Duration
	totalLatencies []time.Duration
}

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
		s.T().Logf("Zeto contract address loaded: %s", s.zetoContractAddress.Hex())
	}
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
	artifactPath := filepath.Join("..", "..", "..", "solidity", "artifacts", "contracts", "zeto_anon.sol", "Zeto_Anon.json")
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
	s.provingTimes = make([]time.Duration, 0, s.numRuns)
	s.miningTimes = make([]time.Duration, 0, s.numRuns)
	s.totalLatencies = make([]time.Duration, 0, s.numRuns)

	// setup the signals for the regular circuits with 2 inputs and 2 outputs
	s.regularTests = make([]*itestcommon.Signals, s.numRuns)
	for i := 0; i < s.numRuns; i++ {
		s.regularTests[i] = itestcommon.NewSignals(s.sender, s.receiver, false, s.db, s.T())
	}

	// setup the signals for the batch circuits with 10 inputs and 10 outputs
	s.batchTests = make([]*itestcommon.Signals, s.numRuns)
	for i := 0; i < s.numRuns; i++ {
		s.batchTests[i] = itestcommon.NewSignals(s.sender, s.receiver, true, s.db, s.T())
	}
}

// loadContractArtifact loads a contract artifact from a JSON file
func loadContractArtifact(artifactPath string) (*ContractArtifact, error) {
	data, err := ioutil.ReadFile(artifactPath)
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

// TestEthereumConnection tests basic connectivity to the Ethereum JSON RPC endpoint
func (s *EthE2ETestSuite) TestEthereumConnection() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Test basic connectivity by getting the latest block number
	blockNumber, err := s.ethClient.BlockNumber(ctx)
	assert.NoError(s.T(), err)
	s.T().Logf("Connected to Ethereum network. Latest block number: %d", blockNumber)

	// Test getting chain ID
	chainID, err := s.ethClient.NetworkID(ctx)
	assert.NoError(s.T(), err)
	s.T().Logf("Network ID: %s", chainID.String())
}

// TestGetAccountBalance tests retrieving account balance from the Ethereum network
func (s *EthE2ETestSuite) TestGetAccountBalance() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	balance, err := s.ethClient.BalanceAt(ctx, s.senderAddress, nil)
	assert.NoError(s.T(), err)
	s.T().Logf("Balance of address %s: %s wei", s.senderAddress.Hex(), balance.String())
}

// TestTransfer demonstrates how to call the transfer function on the Zeto contract
func (s *EthE2ETestSuite) TestTransfer() {
	for i := 0; i < s.numRuns; i++ {
		// Test 1: Call the mint function
		s.T().Logf("=== Run %d/%d: Calling mint function ===", i+1, s.numRuns)
		s.mint(s.regularTests[i].InputCommitments)

		// Example proof bytes - in a real scenario, this would be a valid ZK proof
		proof := s.generateProof(s.regularTests[i])

		// Example data bytes - typically empty for basic transfers
		data := []byte("0x")

		s.T().Logf("=== Testing Transfer Function ===")
		s.T().Logf("Inputs: %v", s.regularTests[i].InputCommitments)
		s.T().Logf("Outputs: %v", s.regularTests[i].OutputCommitments)

		// Call the transfer function
		s.transfer(s.regularTests[i].InputCommitments, s.regularTests[i].OutputCommitments, proof, data)
	}

	// Calculate and display average latencies
	s.calculateAndDisplayAverages()
	s.T().Logf("=== Transfer Test Completed ===")
}

func (s *EthE2ETestSuite) mint(outputCommitments []*big.Int) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Start timing the entire mint process
	mintStartTime := time.Now()

	// Get the nonce for the sender
	nonce, err := s.ethClient.PendingNonceAt(ctx, s.senderAddress)
	assert.NoError(s.T(), err)

	// Get gas price
	gasPrice, err := s.ethClient.SuggestGasPrice(ctx)
	assert.NoError(s.T(), err)

	// Get chain ID
	chainID, err := s.ethClient.NetworkID(ctx)
	assert.NoError(s.T(), err)

	// Create a transactor for the transaction
	auth, err := bind.NewKeyedTransactorWithChainID(s.deployerPrivateKey, chainID)
	assert.NoError(s.T(), err)
	auth.Nonce = big.NewInt(int64(nonce))
	auth.Value = big.NewInt(0)     // No ETH sent with mint
	auth.GasLimit = uint64(500000) // Set a reasonable gas limit
	auth.GasPrice = gasPrice

	// Call mint with UTXO commitments and empty data bytes
	// The ABI expects []*big.Int for uint256[] and []byte for bytes
	tx, err := s.contract.Transact(auth, "mint", outputCommitments, []byte{})
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), tx)

	// Record when transaction was sent
	txSentTime := time.Now()
	transactionLatency := txSentTime.Sub(mintStartTime)

	s.T().Logf("Mint transaction sent: %s", tx.Hash().Hex())
	s.T().Logf("Transaction preparation time: %v", transactionLatency)

	// wait for the transaction to be mined
	receipt, err := s.waitForTransactionReceipt(ctx, tx.Hash())
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), receipt)

	// Record when transaction was mined
	txMinedTime := time.Now()
	miningLatency := txMinedTime.Sub(txSentTime)

	s.T().Logf("Mint transaction mined: %s", tx.Hash().Hex())
	s.T().Logf("Mining time: %v", miningLatency)
	s.T().Logf("Gas used: %d", receipt.GasUsed)
	s.T().Logf("Block number: %d", receipt.BlockNumber.Uint64())
}

func (s *EthE2ETestSuite) generateProof(signals *itestcommon.Signals) *zktypes.ZKProof {
	calc, provingKey, err := itestcommon.LoadCircuit("anon")
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), calc)

	witnessInputs := map[string]interface{}{
		"inputCommitments":      signals.InputCommitments,
		"inputValues":           signals.InputValues,
		"inputSalts":            signals.InputSalts,
		"inputOwnerPrivateKey":  s.sender.PrivateKeyBigInt,
		"outputCommitments":     signals.OutputCommitments,
		"outputValues":          signals.OutputValues,
		"outputSalts":           signals.OutputSalts,
		"outputOwnerPublicKeys": signals.OutputOwnerPublicKeys,
	}

	// generate the witness binary to feed into the prover
	startTime := time.Now()
	witnessBin, err := calc.CalculateWTNSBin(witnessInputs, true)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), witnessBin)

	proof, err := prover.Groth16Prover(provingKey, witnessBin)
	elapsedTime := time.Since(startTime)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), proof)
	s.T().Logf("Proving time: %s\n", elapsedTime)
	s.provingTimes = append(s.provingTimes, elapsedTime)

	return proof
}

// transfer calls the transfer function on the Zeto contract
func (s *EthE2ETestSuite) transfer(inputs []*big.Int, outputs []*big.Int, proof *zktypes.ZKProof, data []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Record start time for latency tracking
	transferStartTime := time.Now()

	// Get the nonce for the sender
	nonce, err := s.ethClient.PendingNonceAt(ctx, s.senderAddress)
	assert.NoError(s.T(), err)

	// Get gas price
	gasPrice, err := s.ethClient.SuggestGasPrice(ctx)
	assert.NoError(s.T(), err)

	// Get chain ID
	chainID, err := s.ethClient.NetworkID(ctx)
	assert.NoError(s.T(), err)

	// Create a transactor for the transaction
	auth, err := bind.NewKeyedTransactorWithChainID(s.deployerPrivateKey, chainID)
	assert.NoError(s.T(), err)
	auth.Nonce = big.NewInt(int64(nonce))
	auth.Value = big.NewInt(0)     // No ETH sent with transfer
	auth.GasLimit = uint64(500000) // Set a reasonable gas limit
	auth.GasPrice = gasPrice

	// Encode the proof for the contract call
	encodedProof, err := util.EncodeProofToBytes(proof)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), encodedProof)

	// Call transfer with inputs, outputs, proof, and data
	tx, err := s.contract.Transact(auth, "transfer", inputs, outputs, encodedProof, data)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), tx)

	// Record when transaction was sent
	txSentTime := time.Now()
	transactionLatency := txSentTime.Sub(transferStartTime)

	s.T().Logf("Transfer transaction sent: %s", tx.Hash().Hex())
	s.T().Logf("Transaction preparation time: %v", transactionLatency)

	// wait for the transaction to be mined
	receipt, err := s.waitForTransactionReceipt(ctx, tx.Hash())
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), receipt)
	assert.Equal(s.T(), receipt.Status, uint64(1))

	// Record when transaction was mined
	txMinedTime := time.Now()
	miningLatency := txMinedTime.Sub(txSentTime)
	totalLatency := txMinedTime.Sub(transferStartTime)

	// Store latency data for averaging
	s.miningTimes = append(s.miningTimes, miningLatency)
	s.totalLatencies = append(s.totalLatencies, totalLatency)

	s.T().Logf("Transfer transaction mined: %s", tx.Hash().Hex())
	s.T().Logf("Mining time: %v", miningLatency)
	s.T().Logf("Total transfer latency: %v", totalLatency)
	s.T().Logf("Gas used: %d", receipt.GasUsed)
	s.T().Logf("Block number: %d", receipt.BlockNumber.Uint64())
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
	var totalPrep, totalMining, totalLatency time.Duration
	var minPrep, maxPrep, minMining, maxMining, minTotal, maxTotal time.Duration

	// Initialize min/max with first values
	minPrep = s.provingTimes[0]
	maxPrep = s.provingTimes[0]
	minMining = s.miningTimes[0]
	maxMining = s.miningTimes[0]
	minTotal = s.totalLatencies[0]
	maxTotal = s.totalLatencies[0]

	for i := 0; i < len(s.provingTimes); i++ {
		// Sum for averages
		totalPrep += s.provingTimes[i]
		totalMining += s.miningTimes[i]
		totalLatency += s.totalLatencies[i]

		// Update min/max for preparation time
		if s.provingTimes[i] < minPrep {
			minPrep = s.provingTimes[i]
		}
		if s.provingTimes[i] > maxPrep {
			maxPrep = s.provingTimes[i]
		}

		// Update min/max for mining time
		if s.miningTimes[i] < minMining {
			minMining = s.miningTimes[i]
		}
		if s.miningTimes[i] > maxMining {
			maxMining = s.miningTimes[i]
		}

		// Update min/max for total latency
		if s.totalLatencies[i] < minTotal {
			minTotal = s.totalLatencies[i]
		}
		if s.totalLatencies[i] > maxTotal {
			maxTotal = s.totalLatencies[i]
		}
	}

	// Calculate averages
	numRuns := len(s.provingTimes)
	avgPrep := totalPrep / time.Duration(numRuns)
	avgMining := totalMining / time.Duration(numRuns)
	avgTotal := totalLatency / time.Duration(numRuns)

	// Display results
	s.T().Logf("")
	s.T().Logf("=== LATENCY STATISTICS (%d runs) ===", numRuns)
	s.T().Logf("")
	s.T().Logf("Proving Time:")
	s.T().Logf("  Average: %v", avgPrep)
	s.T().Logf("  Min:     %v", minPrep)
	s.T().Logf("  Max:     %v", maxPrep)
	s.T().Logf("")
	s.T().Logf("Mining Time:")
	s.T().Logf("  Average: %v", avgMining)
	s.T().Logf("  Min:     %v", minMining)
	s.T().Logf("  Max:     %v", maxMining)
	s.T().Logf("")
	s.T().Logf("Total Transaction Latency:")
	s.T().Logf("  Average: %v", avgTotal)
	s.T().Logf("  Min:     %v", minTotal)
	s.T().Logf("  Max:     %v", maxTotal)
	s.T().Logf("")
	s.T().Logf("=== END LATENCY STATISTICS ===")
}

func TestEthE2ETestSuite(t *testing.T) {
	suite.Run(t, new(EthE2ETestSuite))
}
