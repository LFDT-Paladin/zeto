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

import {ZetoNonFungibleBase} from "./lib/zeto_non_fungible_base.sol";
import {Commonlib} from "./lib/common/common.sol";
import {IZetoInitializable} from "./lib/interfaces/IZetoInitializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @title A sample implementation of a Zeto based non-fungible token with
///        anonymity (no encryption, no nullifier history masking).
/// @author Kaleido, Inc.
/// @notice Decimals: this token uses **4** decimals, inherited from
///         {ZetoCommon.decimals}. NFT integrators rarely consult
///         `decimals()` but it is preserved for ABI symmetry with the
///         fungible siblings.
/// @dev The proof has the following statements:
///        - The sender owns the private key whose public key is part of the pre-image of the input UTXO commitment
///        - The output UTXO commitment is well-formed
///
///      Single-input/single-output transfer. The lock lifecycle is
///      intentionally omitted in this revival; see {ZetoNonFungible}.
contract Zeto_NfAnon is ZetoNonFungibleBase, UUPSUpgradeable {
    /// @dev Lock the implementation contract on construction.
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        string calldata name,
        string calldata symbol,
        address initialOwner,
        IZetoInitializable.VerifiersInfo calldata verifiers
    ) public initializer {
        __ZetoNonFungibleBase_init(name, symbol, initialOwner, verifiers);
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}

    /// @dev Public-inputs layout: [input, output]. `inputsLocked` is
    ///      ignored because this token does not implement the lock
    ///      lifecycle.
    function constructPublicInputs(
        uint256[] memory inputs,
        uint256[] memory outputs,
        bytes memory proof,
        bool /* inputsLocked */
    )
        internal
        pure
        override
        returns (uint256[] memory, Commonlib.Proof memory)
    {
        Commonlib.Proof memory proofStruct = abi.decode(
            proof,
            (Commonlib.Proof)
        );
        uint256[] memory publicInputs = new uint256[](2);
        publicInputs[0] = inputs[0];
        publicInputs[1] = outputs[0];

        return (publicInputs, proofStruct);
    }
}

/// @dev ERC-7201 (`erc7201:zeto.storage.Zeto_NfAnon`).
library Zeto_NfAnonStorage {
    struct Layout {
        uint256 __reserved;
    }

    bytes32 private constant STORAGE_LOCATION =
        0xafcd749646d899cf78964151db8f542448d05467330245e10728559327401500;

    function layout() internal pure returns (Layout storage $) {
        assembly {
            $.slot := STORAGE_LOCATION
        }
    }
}
