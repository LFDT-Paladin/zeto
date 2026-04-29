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
import {NullifierStorage} from "./storage/nullifier.sol";

/// @title A sample base implementation of a Zeto based non-fungible token
///        contract with nullifier-based history masking.
/// @author Kaleido, Inc.
/// @dev Wires {NullifierStorage} into {ZetoNonFungible} for the nullifier
///      flavours of Zeto NF tokens. See {ZetoNonFungible} for the
///      rationale behind the omitted lock lifecycle.
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

/// @dev ERC-7201 (`erc7201:zeto.storage.ZetoNonFungibleNullifier`).
library ZetoNonFungibleNullifierStorage {
    struct Layout {
        uint256 __reserved;
    }

    bytes32 private constant STORAGE_LOCATION =
        0x02976bb09873e8949dece591ee756708ea74c24901fa2000868b92802a9a5200;

    function layout() internal pure returns (Layout storage $) {
        assembly {
            $.slot := STORAGE_LOCATION
        }
    }
}
