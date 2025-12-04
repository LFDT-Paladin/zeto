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
import {Zeto_AnonNullifier} from "./zeto_anon_nullifier.sol";
import {Commonlib} from "./lib/common/common.sol";
import {IZetoInitializable} from "./lib/interfaces/izeto_initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @title A sample implementation of a Zeto based fungible token with anonymity, encryption and history masking
/// @author Kaleido, Inc.
/// @dev The proof has the following statements:
///        - each value in the output commitments must be a positive number in the range 0 ~ (2\*\*40 - 1)
///        - the sum of the nullified values match the sum of output values
///        - the hashes in the input and output match the hash(value, salt, owner public key) formula
///        - the sender possesses the private BabyJubjub key, whose public key is part of the pre-image of the input commitment hashes, which match the corresponding nullifiers
///        - the encrypted value in the input is derived from the receiver's UTXO value and encrypted with a shared secret using the ECDH protocol between the sender and receiver (this guarantees data availability for the receiver)
///        - the nullifiers represent input commitments that are included in a Sparse Merkle Tree represented by the root hash
contract Zeto_AnonEncNullifier is Zeto_AnonNullifier {
    struct _DecodedProof_EncNullifier {
        uint256 root;
        uint256 encryptionNonce;
        uint256[2] ecdhPublicKey;
        uint256[] encryptedValues;
    }

    // Add storage variable to reduce stack usage
    _DecodedProof_EncNullifier private _dpe;

    function initialize(
        string calldata name,
        string calldata symbol,
        address initialOwner,
        IZetoInitializable.VerifiersInfo calldata verifiers
    ) public virtual override initializer {
        __ZetoAnonEncNullifier_init(name, symbol, initialOwner, verifiers);
    }

    function __ZetoAnonEncNullifier_init(
        string calldata name_,
        string calldata symbol_,
        address initialOwner,
        IZetoInitializable.VerifiersInfo calldata verifiers
    ) internal onlyInitializing {
        __ZetoAnonNullifier_init(name_, symbol_, initialOwner, verifiers);
    }

    function emitTransferEvent(
        uint256[] memory nullifiers,
        uint256[] memory outputs,
        bytes memory proof,
        bytes memory data
    ) internal virtual override {
        (_DecodedProof_EncNullifier memory dp, ) = decodeProof_EncNullifier(
            proof
        );
        emit UTXOTransferWithEncryptedValues(
            nullifiers,
            outputs,
            dp.encryptionNonce,
            dp.ecdhPublicKey,
            dp.encryptedValues,
            msg.sender,
            data
        );
    }

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
        (
            _DecodedProof_EncNullifier memory dp,
            Commonlib.Proof memory proofStruct
        ) = decodeProof_EncNullifier(proof);

        // Store the decoded proof in storage to reduce stack usage
        _dpe = dp;

        uint256[] memory extra = extraInputs();
        uint256 size = _calculatePublicInputsSize_EncNullifier(
            nullifiers,
            outputs,
            extra
        );

        uint256[] memory publicInputs = new uint256[](size);
        _fillPublicInputs_EncNullifier(
            publicInputs,
            nullifiers,
            outputs,
            extra
        );
        return (publicInputs, proofStruct);
    }

    function decodeProof_EncNullifier(
        bytes memory proof
    )
        private
        pure
        returns (_DecodedProof_EncNullifier memory, Commonlib.Proof memory)
    {
        (
            uint256 root,
            uint256 encryptionNonce,
            uint256[2] memory ecdhPublicKey,
            uint256[] memory encryptedValues,
            Commonlib.Proof memory proofStruct
        ) = abi.decode(
                proof,
                (uint256, uint256, uint256[2], uint256[], Commonlib.Proof)
            );
        _DecodedProof_EncNullifier memory dp = _DecodedProof_EncNullifier(
            root,
            encryptionNonce,
            ecdhPublicKey,
            encryptedValues
        );
        return (dp, proofStruct);
    }

    function _calculatePublicInputsSize_EncNullifier(
        uint256[] memory nullifiers,
        uint256[] memory outputs,
        uint256[] memory extra
    ) internal view returns (uint256) {
        return
            (nullifiers.length * 2) + // nullifiers and enabled flags
            2 + // root and encryption nonce
            _dpe.ecdhPublicKey.length + // ecdh public key
            _dpe.encryptedValues.length + // encrypted values
            extra.length + // extra inputs
            outputs.length; // outputs
    }

    function _fillPublicInputs_EncNullifier(
        uint256[] memory publicInputs,
        uint256[] memory nullifiers,
        uint256[] memory outputs,
        uint256[] memory extra
    ) internal {
        uint256 piIndex = 0;

        // Split into smaller functions to reduce stack usage
        piIndex = _fillEcdhAndEncryptedValues_EncNullifier(
            publicInputs,
            piIndex
        );
        piIndex = _fillNullifiersAndRoot_EncNullifier(
            publicInputs,
            nullifiers,
            piIndex
        );
        piIndex = _fillEnablesAndExtra_EncNullifier(
            publicInputs,
            nullifiers,
            extra,
            piIndex
        );
        _fillOutputsAndNonce_EncNullifier(publicInputs, outputs, piIndex);
    }

    function _fillEcdhAndEncryptedValues_EncNullifier(
        uint256[] memory publicInputs,
        uint256 piIndex
    ) internal view returns (uint256) {
        // copy the ecdh public key
        for (uint256 i = 0; i < _dpe.ecdhPublicKey.length; ++i) {
            publicInputs[piIndex++] = _dpe.ecdhPublicKey[i];
        }
        // copy the encrypted value, salt and parity bit
        for (uint256 i = 0; i < _dpe.encryptedValues.length; ++i) {
            publicInputs[piIndex++] = _dpe.encryptedValues[i];
        }
        return piIndex;
    }

    function _fillNullifiersAndRoot_EncNullifier(
        uint256[] memory publicInputs,
        uint256[] memory nullifiers,
        uint256 piIndex
    ) internal view returns (uint256) {
        // copy input commitments
        for (uint256 i = 0; i < nullifiers.length; i++) {
            publicInputs[piIndex++] = nullifiers[i];
        }
        // copy root
        publicInputs[piIndex++] = _dpe.root;
        return piIndex;
    }

    function _fillEnablesAndExtra_EncNullifier(
        uint256[] memory publicInputs,
        uint256[] memory nullifiers,
        uint256[] memory extra,
        uint256 piIndex
    ) internal pure returns (uint256) {
        // populate enables
        for (uint256 i = 0; i < nullifiers.length; i++) {
            publicInputs[piIndex++] = (nullifiers[i] == 0) ? 0 : 1;
        }
        // insert extra inputs if any
        for (uint256 i = 0; i < extra.length; i++) {
            publicInputs[piIndex++] = extra[i];
        }
        return piIndex;
    }

    function _fillOutputsAndNonce_EncNullifier(
        uint256[] memory publicInputs,
        uint256[] memory outputs,
        uint256 piIndex
    ) internal view {
        // copy output commitments
        for (uint256 i = 0; i < outputs.length; i++) {
            publicInputs[piIndex++] = outputs[i];
        }
        // copy encryption nonce
        publicInputs[piIndex++] = _dpe.encryptionNonce;
    }

    function extraInputs()
        internal
        view
        virtual
        override
        returns (uint256[] memory)
    {
        // no extra inputs for this contract
        uint256[] memory empty = new uint256[](0);
        return empty;
    }
}
