package eth_e2e

import (
	"context"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTransfer demonstrates how to call the transfer function on the Zeto contract
func (s *EthE2ETestSuite) TestTransfer() {
	useNullifier := s.zetoContractName == "Zeto_AnonNullifier" || s.zetoContractName == "Zeto_AnonNullifierQurrency"
	for i := 0; i < s.numRuns; i++ {
		if useNullifier && i == 0 {
			// verify that the onchain merkle tree root is empty by calling getRoot
			var result []any
			err := s.contract.Call(nil, &result, "getRoot")
			assert.NoError(s.T(), err)
			require.Equal(s.T(), "0", result[0].(*big.Int).String())
		}
		// Test 1: Call the mint function
		s.T().Logf("=== Run %d/%d: Calling mint function ===", i+1, s.numRuns)
		s.mint(s.regularTests[i].InputCommitments)

		// Example proof bytes - in a real scenario, this would be a valid ZK proof
		var proof []byte
		var inputs []*big.Int
		if useNullifier {
			// verify that the onchain merkle tree root is empty by calling getRoot
			var result []any
			err := s.contract.Call(nil, &result, "getRoot")
			assert.NoError(s.T(), err)
			require.Equal(s.T(), s.regularTests[i].Root.String(), result[0].(*big.Int).String())
			s.T().Logf("Onchain SMT root verified to match offchain root: %s", result[0].(*big.Int).String())

			if s.zetoContractName == "Zeto_AnonNullifierQurrency" {
				proof = s.generateProof_anon_qurrency(s.regularTests[i])
			} else {
				proof = s.generateProof_anon_nullifier(s.regularTests[i])
			}
			inputs = s.regularTests[i].Nullifiers
		} else {
			proof = s.generateProof_anon(s.regularTests[i])
			inputs = s.regularTests[i].InputCommitments
		}

		// Example data bytes - typically empty for basic transfers
		data := []byte("0x")

		s.T().Logf("=== Testing Transfer Function ===")

		// Call the transfer function
		s.transfer(inputs, s.regularTests[i].OutputCommitments, proof, data)
	}

	// Calculate and display average latencies
	s.calculateAndDisplayAverages()
	s.T().Logf("=== Transfer Test Completed ===")
}

func (s *EthE2ETestSuite) mint(outputCommitments []*big.Int) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

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
	auth.Value = big.NewInt(0)      // No ETH sent with mint
	auth.GasLimit = uint64(5000000) // Set a reasonable gas limit
	auth.GasPrice = gasPrice

	// Call mint with UTXO commitments and empty data bytes
	// The ABI expects []*big.Int for uint256[] and []byte for bytes
	tx, err := s.contract.Transact(auth, "mint", outputCommitments, []byte{})
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), tx)

	s.T().Logf("Mint transaction sent: %s", tx.Hash().Hex())

	// wait for the transaction to be mined
	receipt, err := s.waitForTransactionReceipt(ctx, tx.Hash())
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), receipt)
	assert.Equal(s.T(), uint64(1), receipt.Status)

	s.T().Logf("Mint transaction mined: %s", tx.Hash().Hex())
	s.T().Logf("Gas used: %d", receipt.GasUsed)
	s.T().Logf("Block number: %d", receipt.BlockNumber.Uint64())
}

// transfer calls the transfer function on the Zeto contract
func (s *EthE2ETestSuite) transfer(inputs []*big.Int, outputs []*big.Int, proof, data []byte) {
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
	auth.Value = big.NewInt(0)       // No ETH sent with transfer
	auth.GasLimit = uint64(50000000) // Set a reasonable gas limit
	auth.GasPrice = gasPrice

	// Call transfer with inputs, outputs, proof, and data
	tx, err := s.contract.Transact(auth, "transfer", inputs, outputs, proof, data)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), tx)

	s.T().Logf("Transfer transaction sent: %s", tx.Hash().Hex())

	// wait for the transaction to be mined
	receipt, err := s.waitForTransactionReceipt(ctx, tx.Hash())
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), receipt)
	assert.Equal(s.T(), uint64(1), receipt.Status)

	// if status is not 1, make an eth_call with the same parameters to get the error message
	if receipt.Status != uint64(1) {
		result, err := s.ethClient.CallContract(ctx, ethereum.CallMsg{
			To:   &s.zetoContractAddress,
			Data: tx.Data(),
		}, nil)
		assert.NoError(s.T(), err)
		s.T().Logf("Error message: %s", result)
	}

	// Record when transaction was mined
	txMinedTime := time.Now()
	txLatency := txMinedTime.Sub(transferStartTime)

	// Store latency data for averaging
	s.txTimes = append(s.txTimes, txLatency)

	s.T().Logf("Transfer transaction mined: %s", tx.Hash().Hex())
	s.T().Logf("Gas used: %d", receipt.GasUsed)
	s.T().Logf("Block number: %d", receipt.BlockNumber.Uint64())

	s.txGasCosts = append(s.txGasCosts, receipt.GasUsed)
}
