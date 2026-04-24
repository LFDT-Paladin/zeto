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

import {ZetoNonFungibleNullifier} from "./lib/zeto_non_fungible_nullifier.sol";
import {Commonlib} from "./lib/common/common.sol";
import {IZetoInitializable} from "./lib/interfaces/IZetoInitializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @title A sample implementation of a Zeto based non-fungible token with
///        anonymity and history masking via nullifiers.
/// @author Kaleido, Inc.
/// @notice Decimals: this token uses **4** decimals, inherited from
///         {ZetoCommon.decimals}. NFT integrators rarely consult
///         `decimals()` but it is preserved for ABI symmetry with the
///         fungible siblings.
/// @dev The proof has the following statements:
///        - The sender owns the private key whose public key is part of the pre-image of the input UTXO commitment
///          (which corresponds to the nullifier).
///        - The nullifier represents an input commitment included in a Sparse Merkle Tree represented by the root hash.
///        - The output UTXO commitment is well-formed.
///
///      The lock lifecycle from the historical {IZetoLockable} stack
///      is not ported in this revival; see {ZetoNonFungible} for the
///      rationale. Public-inputs layout is therefore the simpler
///      `[nullifier, root, output]` triple — no `inputsLocked` branch
///      and no `msg.sender` binding.
contract Zeto_NfAnonNullifier is ZetoNonFungibleNullifier, UUPSUpgradeable {
    /// @dev Reserved storage gap for upgrade safety.
    uint256[50] private __gap;

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
        __ZetoNonFungibleNullifier_init(name, symbol, initialOwner, verifiers);
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}

    /// @dev Public-inputs layout: [nullifier, root, output]. Root
    ///      validation happens here (mirroring {Zeto_AnonNullifier}) so
    ///      that {validateTransactionProposal} does not need to
    ///      pre-decode the proof for that purpose.
    function constructPublicInputs(
        uint256[] memory nullifiers,
        uint256[] memory outputs,
        bytes memory proof,
        bool /* inputsLocked */
    )
        internal
        view
        override
        returns (uint256[] memory, Commonlib.Proof memory)
    {
        (uint256 root, Commonlib.Proof memory proofStruct) = abi.decode(
            proof,
            (uint256, Commonlib.Proof)
        );
        validateRoot(root);

        uint256[] memory publicInputs = new uint256[](3);
        publicInputs[0] = nullifiers[0];
        publicInputs[1] = root;
        publicInputs[2] = outputs[0];
        return (publicInputs, proofStruct);
    }
}
