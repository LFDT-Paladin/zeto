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

import {Commonlib} from "./common/common.sol";
import {IZeto} from "./interfaces/izeto.sol";
import {MAX_SMT_DEPTH} from "./interfaces/izeto.sol";
import {IZetoLockable} from "./interfaces/izeto_lockable.sol";
import {IZetoInitializable} from "./interfaces/izeto_initializable.sol";
import {ZetoNonFungible} from "./zeto_non_fungible.sol";
import {IZetoStorage} from "./interfaces/izeto_storage.sol";
import {NullifierStorage} from "./storage/nullifier.sol";

/// @title A sample base implementation of a Zeto based token contract with nullifiers
/// @author Kaleido, Inc.
/// @dev Implements common functionalities of Zeto based tokens using nullifiers
abstract contract ZetoNonFungibleNullifier is ZetoNonFungible {
    function __ZetoNonFungibleNullifier_init(
        string calldata name_,
        string calldata symbol_,
        address initialOwner,
        IZetoInitializable.VerifiersInfo calldata verifiers
    ) internal onlyInitializing {
        IZetoStorage storage_ = new NullifierStorage();
        __ZetoNonFungible_init(
            name_,
            symbol_,
            initialOwner,
            verifiers,
            storage_
        );
    }
}
