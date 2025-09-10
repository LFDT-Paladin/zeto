package eth_e2e

import (
	"context"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/hyperledger-labs/zeto/go-sdk/integration-test/common"
	"github.com/hyperledger-labs/zeto/go-sdk/internal/util"
	"github.com/iden3/go-rapidsnark/prover"
	"github.com/iden3/go-rapidsnark/types"
	"github.com/stretchr/testify/assert"
)

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

func (s *EthE2ETestSuite) generateProof(signals *common.Signals) *types.ZKProof {
	calc, provingKey, err := common.LoadCircuit("anon")
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
func (s *EthE2ETestSuite) transfer(inputs []*big.Int, outputs []*big.Int, proof *types.ZKProof, data []byte) {
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
