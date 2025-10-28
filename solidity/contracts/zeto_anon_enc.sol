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
import {Commonlib} from "./lib/common/common.sol";
import {IZetoInitializable} from "./lib/interfaces/izeto_initializable.sol";
import {Zeto_Anon} from "./zeto_anon.sol";

/// @title A sample implementation of a Zeto based fungible token with anonymity, and encryption
/// @author Kaleido, Inc.
/// @dev The proof has the following statements:
///        - each value in the output commitments must be a positive number in the range 0 ~ (2\*\*40 - 1)
///        - the sum of the input values match the sum of output values
///        - the hashes in the input and output match the hash(value, salt, owner public key) formula
///        - the sender possesses the private BabyJubjub key, whose public key is part of the pre-image of the input commitment hashes
///        - the encrypted value in the input is derived from the receiver's UTXO value and encrypted with a shared secret using
///          the ECDH protocol between the sender and receiver (this guarantees data availability for the receiver)
contract Zeto_AnonEnc is Zeto_Anon {
    function initialize(
        string calldata name,
        string calldata symbol,
        address initialOwner,
        IZetoInitializable.VerifiersInfo calldata verifiers
    ) public virtual override initializer {
        __ZetoAnon_init(name, symbol, initialOwner, verifiers);
    }

    function emitTransferEvent(
        uint256[] memory inputs,
        uint256[] memory outputs,
        bytes memory proof,
        bytes memory data
    ) internal virtual override {
        (
            uint256 encryptionNonce,
            uint256[2] memory ecdhPublicKey,
            uint256[] memory encryptedValues
        ) = abi.decode(proof, (uint256, uint256[2], uint256[]));
        emit UTXOTransferWithEncryptedValues(
            inputs,
            outputs,
            encryptionNonce,
            ecdhPublicKey,
            encryptedValues,
            msg.sender,
            data
        );
    }

    struct _DecodedProof {
        uint256 encryptionNonce;
        uint256[2] ecdhPublicKey;
        uint256[] encryptedValues;
    }

    function constructPublicInputs(
        uint256[] memory inputs,
        uint256[] memory outputs,
        bytes memory proof,
        bool isLocked
    )
        internal
        view
        virtual
        override
        returns (uint256[] memory, Commonlib.Proof memory)
    {
        (
            uint256 encryptionNonce,
            uint256[2] memory ecdhPublicKey,
            uint256[] memory encryptedValues,
            Commonlib.Proof memory proofStruct
        ) = abi.decode(
                proof,
                (uint256, uint256[2], uint256[], Commonlib.Proof)
            );
        _DecodedProof memory dp = _DecodedProof(
            encryptionNonce,
            ecdhPublicKey,
            encryptedValues
        );
        uint256 size = ecdhPublicKey.length +
            encryptedValues.length +
            inputs.length +
            outputs.length +
            1; // encryptionNonce
        uint256[] memory publicInputs = new uint256[](size);
        _fillPublicInputs(publicInputs, inputs, outputs, dp);

        return (publicInputs, proofStruct);
    }

    function _fillPublicInputs(
        uint256[] memory publicInputs,
        uint256[] memory inputs,
        uint256[] memory outputs,
        _DecodedProof memory dp
    ) internal pure {
        uint256 piIndex = 0;
        // copy the ecdh public key
        for (uint256 i = 0; i < dp.ecdhPublicKey.length; ++i) {
            publicInputs[piIndex++] = dp.ecdhPublicKey[i];
        }

        // copy the encrypted value, salt and parity bit
        for (uint256 i = 0; i < dp.encryptedValues.length; ++i) {
            publicInputs[piIndex++] = dp.encryptedValues[i];
        }
        // copy input commitments
        for (uint256 i = 0; i < inputs.length; i++) {
            publicInputs[piIndex++] = inputs[i];
        }

        // copy output commitments
        for (uint256 i = 0; i < outputs.length; i++) {
            publicInputs[piIndex++] = outputs[i];
        }

        // copy encryption nonce
        publicInputs[piIndex++] = dp.encryptionNonce;
    }
}
