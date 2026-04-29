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

import {IZetoInitializable} from "./interfaces/IZetoInitializable.sol";
import {ZetoFungible} from "./zeto_fungible.sol";
import {IZetoStorage} from "./interfaces/IZetoStorage.sol";
import {BaseStorage} from "./storage/base.sol";

/// @title A sample base implementation of a Zeto based fungible token contract
///        WITHOUT nullifiers. Each UTXO's spending status is explicitly tracked
///        in the {BaseStorage} ledger.
/// @author Kaleido, Inc.
/// @dev Sibling of {ZetoFungibleNullifier}. The two differ only in the storage
///      backend wired into {ZetoFungible}: this contract uses {BaseStorage},
///      which records `(utxo => UTXOStatus)` for both regular and locked UTXOs;
///      the nullifier sibling uses {NullifierStorage}, which records spent
///      nullifiers in a Sparse Merkle Tree.
///
///      The locking lifecycle (createLock / updateLock / delegateLock /
///      spendLock / cancelLock) is inherited unchanged from {ZetoFungible}
///      and is therefore identical across both backends. The only contract
///      that differs between the two siblings is the leaf token (e.g.
///      Zeto_Anon vs Zeto_AnonNullifier), which supplies the
///      circuit-specific `constructPublicInputs` implementation.
///
///      Future non-nullifier-only state belongs in {ZetoFungibleBaseStorage}
///      below — append fields there on upgrade instead of `__gap`.
abstract contract ZetoFungibleBase is ZetoFungible {
    function __ZetoFungibleBase_init(
        string calldata name_,
        string calldata symbol_,
        address initialOwner,
        IZetoInitializable.VerifiersInfo calldata verifiers
    ) internal onlyInitializing {
        IZetoStorage storage_ = new BaseStorage();
        __ZetoFungible_init(name_, symbol_, initialOwner, verifiers, storage_);
    }
}

/// @dev ERC-7201 (`erc7201:zeto.storage.ZetoFungibleBase`): reserved for
///      non-nullifier fungible leaf extensions.
library ZetoFungibleBaseStorage {
    struct Layout {
        uint256 __reserved;
    }

    bytes32 private constant STORAGE_LOCATION =
        0x06a87037c58e5288ef9ee2ed0d7efb7c68b30748ac0ed4d5eb8700eb60966f00;

    function layout() internal pure returns (Layout storage $) {
        assembly {
            $.slot := STORAGE_LOCATION
        }
    }
}
