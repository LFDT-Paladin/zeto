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
import {ZetoNonFungible} from "./zeto_non_fungible.sol";
import {IZetoStorage} from "./interfaces/IZetoStorage.sol";
import {BaseStorage} from "./storage/base.sol";

/// @title A sample base implementation of a Zeto based non-fungible token contract
///        without using nullifiers. Each UTXO's spending status is explicitly tracked.
/// @author Kaleido, Inc.
/// @dev Wires {BaseStorage} into {ZetoNonFungible} for non-nullifier
///      flavours of Zeto NF tokens. See {ZetoNonFungible} for the
///      rationale behind the omitted lock lifecycle.
abstract contract ZetoNonFungibleBase is ZetoNonFungible {
    /// @dev Reserved storage gap for upgrade safety. See
    ///      {ZetoNonFungible.__gap} for sizing rationale.
    uint256[50] private __gap;

    function __ZetoNonFungibleBase_init(
        string calldata name_,
        string calldata symbol_,
        address initialOwner,
        IZetoInitializable.VerifiersInfo calldata verifiers
    ) internal onlyInitializing {
        IZetoStorage storage_ = new BaseStorage();
        __ZetoNonFungible_init(
            name_,
            symbol_,
            initialOwner,
            verifiers,
            storage_
        );
    }
}
