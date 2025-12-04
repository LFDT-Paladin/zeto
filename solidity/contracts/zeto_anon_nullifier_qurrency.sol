// Copyright © 2025 Kaleido, Inc.
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

import {PoseidonUnit5L} from "@iden3/contracts/lib/Poseidon.sol";
import {IZeto} from "./lib/interfaces/izeto.sol";
import {MAX_BATCH} from "./lib/interfaces/izeto.sol";
import {Zeto_AnonNullifier} from "./zeto_anon_nullifier.sol";
import {Commonlib} from "./lib/common/common.sol";
import {IZetoInitializable} from "./lib/interfaces/izeto_initializable.sol";

/// @title A sample implementation of a Zeto based fungible token with anonymity and history masking
/// @author Kaleido, Inc.
/// @dev The proof has the following statements:
///        - each value in the output commitments must be a positive number in the range 0 ~ (2\*\*40 - 1)
///        - the sum of the nullified values match the sum of output values
///        - the hashes in the input and output match the hash(value, salt, owner public key) formula
///        - the sender possesses the private BabyJubjub key, whose public key is part of the pre-image of the input commitment hashes, which match the corresponding nullifiers
///        - the nullifiers represent input commitments that are included in a Sparse Merkle Tree represented by the root hash
contract Zeto_AnonNullifierQurrency is Zeto_AnonNullifier {
    struct _DecodedProof_Qurrency {
        uint256 root;
        uint256 encryptionNonce;
        uint256[] encryptedValues;
        uint256[25] encapsulatedSharedSecret;
    }

    // Add storage variable to reduce stack usage
    _DecodedProof_Qurrency private _dpq;
    // Additional storage variables to reduce stack usage
    uint256[] private _publicInputs;
    uint256 private _piIndex;

    function initialize(
        string calldata name,
        string calldata symbol,
        address initialOwner,
        IZetoInitializable.VerifiersInfo calldata verifiers
    ) public override initializer {
        __ZetoAnonNullifier_init(name, symbol, initialOwner, verifiers);
    }

    function emitTransferEvent(
        uint256[] memory nullifiers,
        uint256[] memory outputs,
        bytes memory proof,
        bytes memory data
    ) internal override {
        (
            _DecodedProof_Qurrency memory dp,
            Commonlib.Proof memory proofStruct
        ) = decodeProof_Qurrency(proof);

        emit UTXOTransferWithMlkemEncryptedValues(
            nullifiers,
            outputs,
            dp.encryptionNonce,
            dp.encapsulatedSharedSecret,
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
            _DecodedProof_Qurrency memory dp,
            Commonlib.Proof memory proofStruct
        ) = decodeProof_Qurrency(proof);

        // Store the decoded proof in storage to reduce stack usage
        _dpq = dp;

        uint256 size = _calculatePublicInputsSize(
            nullifiers,
            outputs,
            inputsLocked
        );

        _fillPublicInputs(size, nullifiers, outputs, inputsLocked);
        return (_publicInputs, proofStruct);
    }

    function decodeProof_Qurrency(
        bytes memory proof
    )
        internal
        pure
        returns (
            _DecodedProof_Qurrency memory dp,
            Commonlib.Proof memory proofStruct
        )
    {
        (
            dp.root,
            dp.encryptionNonce,
            dp.encryptedValues,
            dp.encapsulatedSharedSecret,
            proofStruct
        ) = abi.decode(
            proof,
            (uint256, uint256, uint256[], uint256[25], Commonlib.Proof)
        );
        return (dp, proofStruct);
    }

    function _calculatePublicInputsSize(
        uint256[] memory nullifiers,
        uint256[] memory outputs,
        bool inputsLocked
    ) internal view returns (uint256) {
        // the public inputs for the non-batch proof have the following structure:
        //  - 25 elements for the ML-KEM encapsulated shared secret
        //  - 16 or 64 elements for the encrypted values (3n+1 for 14 or 62 encyrpted elements)
        //  - 2 or 10 elements for the nullifiers
        //  - 1 element for the root hash
        //  - 2 or 10 elements for the "enabled" flags (1 for each nullifier)
        //  - 2 or 10 elements for the output commitments
        return
            _dpq.encapsulatedSharedSecret.length +
            _dpq.encryptedValues.length +
            (nullifiers.length * 2) + // nullifiers and the enabled flags
            outputs.length +
            2 + // root and encryptionNonce
            (inputsLocked ? 1 : 0); // lock delegate if locked
    }

    function _fillPublicInputs(
        uint256 size,
        uint256[] memory nullifiers,
        uint256[] memory outputs,
        bool inputsLocked
    ) internal {
        _publicInputs = new uint256[](size);
        _piIndex = 0;

        // Split into smaller functions to reduce stack usage
        _fillEncapsulatedSharedSecret();
        _fillEncryptedValues();
        _fillNullifiersAndLockDelegate(nullifiers, inputsLocked);
        _fillRootAndEnables(nullifiers);
        _fillOutputs(outputs);
    }

    function _fillEncapsulatedSharedSecret() internal {
        // copy the ML-KEM encapsulated shared secret
        for (uint256 i = 0; i < _dpq.encapsulatedSharedSecret.length; ++i) {
            _publicInputs[_piIndex++] = _dpq.encapsulatedSharedSecret[i];
        }
    }

    function _fillEncryptedValues() internal {
        // copy the encrypted output values
        for (uint256 i = 0; i < _dpq.encryptedValues.length; ++i) {
            _publicInputs[_piIndex++] = _dpq.encryptedValues[i];
        }
    }

    function _fillNullifiersAndLockDelegate(
        uint256[] memory nullifiers,
        bool inputsLocked
    ) internal {
        // copy nullifiers
        for (uint256 i = 0; i < nullifiers.length; i++) {
            _publicInputs[_piIndex++] = nullifiers[i];
        }
        // when verifying locked transfers, additional public input
        // for the lock delegate
        if (inputsLocked) {
            _publicInputs[_piIndex++] = uint256(uint160(msg.sender));
        }
    }

    function _fillRootAndEnables(uint256[] memory nullifiers) internal {
        // copy root
        _publicInputs[_piIndex++] = _dpq.root;
        // populate enables
        for (uint256 i = 0; i < nullifiers.length; i++) {
            _publicInputs[_piIndex++] = (nullifiers[i] == 0) ? 0 : 1;
        }
    }

    function _fillOutputs(uint256[] memory outputs) internal {
        // copy output commitments
        for (uint256 i = 0; i < outputs.length; i++) {
            _publicInputs[_piIndex++] = outputs[i];
        }
    }
}
