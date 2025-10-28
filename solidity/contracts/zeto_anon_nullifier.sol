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

import {IZeto} from "./lib/interfaces/izeto.sol";
import {MAX_BATCH} from "./lib/interfaces/izeto.sol";
import {ZetoFungibleNullifier} from "./lib/zeto_fungible_nullifier.sol";
import {Commonlib} from "./lib/common/common.sol";
import {IZetoInitializable} from "./lib/interfaces/izeto_initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @title A sample implementation of a Zeto based fungible token with anonymity and history masking
/// @author Kaleido, Inc.
/// @dev The proof has the following statements:
///        - each value in the output commitments must be a positive number in the range 0 ~ (2\*\*40 - 1)
///        - the sum of the nullified values match the sum of output values
///        - the hashes in the input and output match the hash(value, salt, owner public key) formula
///        - the sender possesses the private BabyJubjub key, whose public key is part of the pre-image of the input commitment hashes, which match the corresponding nullifiers
///        - the nullifiers represent input commitments that are included in a Sparse Merkle Tree represented by the root hash
contract Zeto_AnonNullifier is ZetoFungibleNullifier, UUPSUpgradeable {
    function initialize(
        string calldata name,
        string calldata symbol,
        address initialOwner,
        IZetoInitializable.VerifiersInfo calldata verifiers
    ) public virtual initializer {
        __ZetoAnonNullifier_init(name, symbol, initialOwner, verifiers);
    }

    function __ZetoAnonNullifier_init(
        string calldata name_,
        string calldata symbol_,
        address initialOwner,
        IZetoInitializable.VerifiersInfo calldata verifiers
    ) internal onlyInitializing {
        __ZetoFungibleNullifier_init(name_, symbol_, initialOwner, verifiers);
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}

    function constructPublicInputs(
        uint256[] memory nullifiers,
        uint256[] memory outputs,
        bytes memory proof,
        bool inputsLocked
    )
        internal
        virtual
        override
        returns (uint256[] memory, Commonlib.Proof memory)
    {
        // Decode the proof to extract root and proof structure
        (uint256 root, Commonlib.Proof memory proofStruct) = abi.decode(
            proof,
            (uint256, Commonlib.Proof)
        );

        // Get extra inputs from derived contracts
        uint256[] memory extra = extraInputs();

        // Calculate the total size needed for public inputs
        uint256 size = _calculatePublicInputsSize(
            nullifiers,
            outputs,
            extra,
            inputsLocked
        );

        // Create and populate the public inputs array
        uint256[] memory publicInputs = new uint256[](size);
        _fillPublicInputs(
            publicInputs,
            nullifiers,
            outputs,
            extra,
            root,
            inputsLocked
        );

        return (publicInputs, proofStruct);
    }

    function _calculatePublicInputsSize(
        uint256[] memory nullifiers,
        uint256[] memory outputs,
        uint256[] memory extra,
        bool inputsLocked
    ) internal pure returns (uint256 size) {
        size =
            (nullifiers.length * 2) + // nullifiers and enabled flags
            (inputsLocked ? 1 : 0) + // lock delegate if locked
            1 + // root
            extra.length + // extra inputs
            outputs.length; // output commitments
    }

    function _fillPublicInputs(
        uint256[] memory publicInputs,
        uint256[] memory nullifiers,
        uint256[] memory outputs,
        uint256[] memory extra,
        uint256 root,
        bool inputsLocked
    ) internal view {
        uint256 piIndex = 0;

        // Copy nullifiers
        piIndex = _fillNullifiers_Nullifier(publicInputs, nullifiers, piIndex);

        // Add lock delegate if inputs are locked
        if (inputsLocked) {
            publicInputs[piIndex++] = uint256(uint160(msg.sender));
        }

        // Copy root
        publicInputs[piIndex++] = root;

        // Populate enabled flags
        piIndex = _fillEnabledFlags_Nullifier(
            publicInputs,
            nullifiers,
            piIndex
        );

        // Copy extra inputs
        piIndex = _fillExtraInputs_Nullifier(publicInputs, extra, piIndex);

        // Copy output commitments
        _fillOutputCommitments_Nullifier(publicInputs, outputs, piIndex);
    }

    function _fillNullifiers_Nullifier(
        uint256[] memory publicInputs,
        uint256[] memory nullifiers,
        uint256 startIndex
    ) internal pure returns (uint256 nextIndex) {
        uint256 piIndex = startIndex;
        for (uint256 i = 0; i < nullifiers.length; i++) {
            publicInputs[piIndex++] = nullifiers[i];
        }
        return piIndex;
    }

    function _fillEnabledFlags_Nullifier(
        uint256[] memory publicInputs,
        uint256[] memory nullifiers,
        uint256 startIndex
    ) internal pure returns (uint256 nextIndex) {
        uint256 piIndex = startIndex;
        for (uint256 i = 0; i < nullifiers.length; i++) {
            publicInputs[piIndex++] = (nullifiers[i] == 0) ? 0 : 1;
        }
        return piIndex;
    }

    function _fillExtraInputs_Nullifier(
        uint256[] memory publicInputs,
        uint256[] memory extra,
        uint256 startIndex
    ) internal pure returns (uint256 nextIndex) {
        uint256 piIndex = startIndex;
        for (uint256 i = 0; i < extra.length; i++) {
            publicInputs[piIndex++] = extra[i];
        }
        return piIndex;
    }

    function _fillOutputCommitments_Nullifier(
        uint256[] memory publicInputs,
        uint256[] memory outputs,
        uint256 startIndex
    ) internal pure {
        uint256 piIndex = startIndex;
        for (uint256 i = 0; i < outputs.length; i++) {
            publicInputs[piIndex++] = outputs[i];
        }
    }

    function extraInputs() internal view virtual returns (uint256[] memory) {
        // no extra inputs for this contract
        uint256[] memory empty = new uint256[](0);
        return empty;
    }

    function constructPublicInputsForLock(
        uint256[] memory inputs,
        uint256[] memory outputs,
        uint256[] memory lockedOutputs,
        bytes memory proof
    )
        internal
        virtual
        override
        returns (uint256[] memory, Commonlib.Proof memory)
    {
        uint256[] memory allOutputs = new uint256[](
            outputs.length + lockedOutputs.length
        );
        for (uint256 i = 0; i < outputs.length; i++) {
            allOutputs[i] = outputs[i];
        }
        for (uint256 i = 0; i < lockedOutputs.length; i++) {
            allOutputs[outputs.length + i] = lockedOutputs[i];
        }

        return constructPublicInputs(inputs, allOutputs, proof, false);
    }

    function validateTransactionProposal(
        uint256[] memory inputs,
        uint256[] memory outputs,
        uint256[] memory lockedOutputs,
        bytes memory proof,
        bool inputsLocked
    ) internal view virtual override {
        super.validateTransactionProposal(
            inputs,
            outputs,
            lockedOutputs,
            proof,
            inputsLocked
        );
        uint256 root = abi.decode(proof, (uint256)); // only decode the root from the proof, which is the first 32 bytes
        validateRoot(root, inputsLocked);
    }
}
