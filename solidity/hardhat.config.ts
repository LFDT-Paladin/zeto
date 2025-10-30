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

import { HardhatUserConfig, vars } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "@openzeppelin/hardhat-upgrades";
import "@fhevm/hardhat-plugin";
import crypto from "crypto";

const keys = [
  process.env.ETH_PRIVATE_KEY_1 || crypto.randomBytes(32).toString("hex"),
  process.env.ETH_PRIVATE_KEY_2 || crypto.randomBytes(32).toString("hex"),
  crypto.randomBytes(32).toString("hex"),
  crypto.randomBytes(32).toString("hex"),
  crypto.randomBytes(32).toString("hex"),
];

// Add your Sepolia account private key to the configuration variables
// Beware: NEVER put real Ether into testing accounts
const SEPOLIA_PRIVATE_KEY_1 = process.env.SEPOLIA_PRIVATE_KEY_1 || crypto.randomBytes(32).toString("hex");
const SEPOLIA_PRIVATE_KEY_2 = process.env.SEPOLIA_PRIVATE_KEY_2 || crypto.randomBytes(32).toString("hex");

// set your Sepolia JSON RPC URL in the environment variable SEPOLIA_JSON_RPC_URL
const SEPOLIA_JSON_RPC_URL = process.env.SEPOLIA_JSON_RPC_URL || "";

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.27",
    settings: {
      optimizer: {
        enabled: true,
        runs: 25,
      },
      viaIR: true,
      evmVersion: 'cancun',
    },
  },
  paths: {
    sources: "contracts"
  },
  networks: {
    hardhat: {
      // a small number of verifiers are bigger than the default 24576 bytes
      // so we need to allow unlimited contract size to avoid test errors
      allowUnlimitedContractSize: true,
    },
    besu: {
      url: "http://localhost:8545",
      accounts: keys,
      gasPrice: 0,
    },
    sepolia: {
      url: `${SEPOLIA_JSON_RPC_URL}`,
      accounts: [SEPOLIA_PRIVATE_KEY_1, SEPOLIA_PRIVATE_KEY_2, ...keys],
    }
  }
};

export default config;
