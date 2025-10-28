package eth_e2e

import (
	"context"
	"time"

	"github.com/stretchr/testify/assert"
)

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
