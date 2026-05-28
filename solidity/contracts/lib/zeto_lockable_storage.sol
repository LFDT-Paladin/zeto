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

/// @dev ERC-7201 (`erc7201:zeto.storage.ZetoLockable`): lock lifecycle state for
///      {ZetoLockableLib} and embedding token contracts.
library ZetoLockableStorage {
    struct ZetoLockInfo {
        address owner;
        address spender;
        bytes32 spendCommitment;
        bytes32 cancelCommitment;
        uint256[] lockedInputs;
    }

    struct Layout {
        mapping(bytes32 => ZetoLockInfo) locks;
        mapping(address => mapping(bytes32 => bool)) txIds;
        mapping(uint256 => address) utxoDelegates;
    }

    bytes32 private constant STORAGE_LOCATION =
        0x6f84b5947db308f6274c3bdf3450b8e85913b258c3b2e7abbddf0986236a4900;

    function layout() internal pure returns (Layout storage $) {
        assembly {
            $.slot := STORAGE_LOCATION
        }
    }
}
