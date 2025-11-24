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
pragma solidity ^0.8.27;

uint256 constant MAX_BATCH = 10;
uint256 constant MAX_SMT_DEPTH = 64;

interface IZetoConstants {
    error UTXODuplicate(uint256 utxo);
    error UTXOArrayTooLarge(uint256 maxAllowed);
    error UTXONotMinted(uint256 utxo);
    error UTXOAlreadyOwned(uint256 utxo);
    error UTXOAlreadySpent(uint256 utxo);

    event UTXOMint(uint256[] outputs, address indexed submitter, bytes data);
    event UTXOBurn(
        uint256[] inputs,
        uint256 output,
        address indexed submitter,
        bytes data
    );
    event UTXOTransfer(
        uint256[] inputs,
        uint256[] outputs,
        address indexed submitter,
        bytes data
    );
    event UTXOTransferWithEncryptedValues(
        uint256[] inputs,
        uint256[] outputs,
        uint256 encryptionNonce,
        uint256[2] ecdhPublicKey,
        uint256[] encryptedValues,
        address indexed submitter,
        bytes data
    );
    event UTXOTransferWithMlkemEncryptedValues(
        uint256[] inputs,
        uint256[] outputs,
        uint256 encryptionNonce,
        uint256[25] encapsulatedSharedSecret,
        uint256[] encryptedValues,
        address indexed submitter,
        bytes data
    );
    event UTXOWithdraw(
        uint256 amount,
        uint256[] inputs,
        uint256 output,
        address indexed submitter,
        bytes data
    );
}

interface IZeto is IZetoConstants {
    /**
     * @dev Returns the name of the token.
     */
    function name() external view returns (string memory);

    /**
     * @dev Returns the symbol of the token.
     */
    function symbol() external view returns (string memory);

    /**
     * @dev Returns the decimals places of the token.
     */
    function decimals() external view returns (uint8);
}
