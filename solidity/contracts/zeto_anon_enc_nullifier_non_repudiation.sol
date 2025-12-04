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

import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Commonlib} from "./lib/common/common.sol";
import {IZetoInitializable} from "./lib/interfaces/izeto_initializable.sol";
import {Zeto_AnonEncNullifier} from "./zeto_anon_enc_nullifier.sol";

/// @title A sample implementation of a Zeto based fungible token with anonymity, encryption and history masking
/// @author Kaleido, Inc.
/// @dev The proof has the following statements:
///        - each value in the output commitments must be a positive number in the range 0 ~ (2\*\*40 - 1)
///        - the sum of the nullified values match the sum of output values
///        - the hashes in the input and output match the hash(value, salt, owner public key) formula
///        - the sender possesses the private BabyJubjub key, whose public key is part of the pre-image of the input commitment hashes, which match the corresponding nullifiers
///        - the encrypted value in the input is derived from the receiver's UTXO value and encrypted with a shared secret using the ECDH protocol between the sender and receiver (this guarantees data availability for the receiver)
///        - the nullifiers represent input commitments that are included in a Sparse Merkle Tree represented by the root hash
contract Zeto_AnonEncNullifierNonRepudiation is Zeto_AnonEncNullifier {
    struct _DecodedProof_NonRepudiation {
        uint256 root;
        uint256 encryptionNonce;
        uint256[2] ecdhPublicKey;
        uint256[] encryptedValuesForReceiver;
        uint256[] encryptedValuesForAuthority;
    }

    // Add storage variable to reduce stack usage
    _DecodedProof_NonRepudiation private _dpnr;

    event UTXOTransferNonRepudiation(
        uint256[] inputs,
        uint256[] outputs,
        uint256 encryptionNonce,
        uint256[2] ecdhPublicKey,
        uint256[] encryptedValuesForReceiver,
        uint256[] encryptedValuesForAuthority,
        address indexed submitter,
        bytes data
    );
    // the arbiter public key that must be used to
    // encrypt the secrets of every transaction
    uint256[2] private arbiter;

    function initialize(
        string calldata name,
        string calldata symbol,
        address initialOwner,
        IZetoInitializable.VerifiersInfo calldata verifiers
    ) public virtual override initializer {
        __ZetoAnonEncNullifierNonRepudiation_init(
            name,
            symbol,
            initialOwner,
            verifiers
        );
    }

    function __ZetoAnonEncNullifierNonRepudiation_init(
        string calldata name_,
        string calldata symbol_,
        address initialOwner,
        IZetoInitializable.VerifiersInfo calldata verifiers
    ) internal onlyInitializing {
        __ZetoAnonEncNullifier_init(name_, symbol_, initialOwner, verifiers);
    }

    function setArbiter(uint256[2] memory _arbiter) public onlyOwner {
        arbiter = _arbiter;
    }

    function getArbiter() public view returns (uint256[2] memory) {
        return arbiter;
    }

    function emitTransferEvent(
        uint256[] memory nullifiers,
        uint256[] memory outputs,
        bytes memory proof,
        bytes memory data
    ) internal override {
        (_DecodedProof_NonRepudiation memory dp, ) = decodeProof_NonRepudiation(
            proof
        );
        emit UTXOTransferNonRepudiation(
            nullifiers,
            outputs,
            dp.encryptionNonce,
            dp.ecdhPublicKey,
            dp.encryptedValuesForReceiver,
            dp.encryptedValuesForAuthority,
            msg.sender,
            data
        );
    }

    function validateTransactionProposal(
        uint256[] memory nullifiers,
        uint256[] memory outputs,
        uint256[] memory lockedOutputs,
        bytes memory proof,
        bool inputsLocked
    ) internal view override {
        super.validateTransactionProposal(
            nullifiers,
            outputs,
            lockedOutputs,
            proof,
            inputsLocked
        );
        // Check the encrypted values for authority
        uint256 root = abi.decode(proof, (uint256));
        validateRoot(root, inputsLocked);
    }

    function constructPublicInputs(
        uint256[] memory nullifiers,
        uint256[] memory outputs,
        bytes memory proof,
        bool inputsLocked
    ) internal override returns (uint256[] memory, Commonlib.Proof memory) {
        (
            _DecodedProof_NonRepudiation memory dp,
            Commonlib.Proof memory proofStruct
        ) = decodeProof_NonRepudiation(proof);
        // Store the decoded proof in storage to reduce stack usage
        _dpnr = dp;
        uint256 size = _calculatePublicInputsSize_NonRepudiation(
            nullifiers,
            outputs
        );
        uint256[] memory publicInputs = new uint256[](size);
        _fillPublicInputs_NonRepudiation(publicInputs, nullifiers, outputs);

        return (publicInputs, proofStruct);
    }

    function decodeProof_NonRepudiation(
        bytes memory proof
    )
        private
        pure
        returns (
            _DecodedProof_NonRepudiation memory dp,
            Commonlib.Proof memory proofStruct
        )
    {
        (
            dp.root,
            dp.encryptionNonce,
            dp.ecdhPublicKey,
            dp.encryptedValuesForReceiver,
            dp.encryptedValuesForAuthority,
            proofStruct
        ) = abi.decode(
            proof,
            (
                uint256,
                uint256,
                uint256[2],
                uint256[],
                uint256[],
                Commonlib.Proof
            )
        );
    }

    function _calculatePublicInputsSize_NonRepudiation(
        uint256[] memory nullifiers,
        uint256[] memory outputs
    ) internal view returns (uint256) {
        return
            _dpnr.ecdhPublicKey.length + // ecdh public key
            _dpnr.encryptedValuesForReceiver.length +
            _dpnr.encryptedValuesForAuthority.length +
            (nullifiers.length * 2) + // nullifiers and enabled flags
            outputs.length +
            2 + // root and encryptionNonce
            2; // arbiter public key
    }

    function _fillPublicInputs_NonRepudiation(
        uint256[] memory publicInputs,
        uint256[] memory nullifiers,
        uint256[] memory outputs
    ) internal {
        uint256 piIndex = 0;

        // Split into smaller functions to reduce stack usage
        piIndex = _fillEcdhAndEncryptedValues_NonRepudiation(
            publicInputs,
            piIndex
        );
        piIndex = _fillNullifiersAndRoot_NonRepudiation(
            publicInputs,
            nullifiers,
            piIndex
        );
        piIndex = _fillEnablesAndOutputs_NonRepudiation(
            publicInputs,
            nullifiers,
            outputs,
            piIndex
        );
        _fillNonceAndArbiter_NonRepudiation(publicInputs, piIndex);
    }

    function _fillEcdhAndEncryptedValues_NonRepudiation(
        uint256[] memory publicInputs,
        uint256 piIndex
    ) internal view returns (uint256) {
        // copy the ecdh public key
        for (uint256 i = 0; i < _dpnr.ecdhPublicKey.length; ++i) {
            publicInputs[piIndex++] = _dpnr.ecdhPublicKey[i];
        }
        // copy the encrypted value, salt and parity bit for receiver
        for (uint256 i = 0; i < _dpnr.encryptedValuesForReceiver.length; ++i) {
            publicInputs[piIndex++] = _dpnr.encryptedValuesForReceiver[i];
        }
        // copy the encrypted value, salt and parity bit for authority
        for (uint256 i = 0; i < _dpnr.encryptedValuesForAuthority.length; ++i) {
            publicInputs[piIndex++] = _dpnr.encryptedValuesForAuthority[i];
        }
        return piIndex;
    }

    function _fillNullifiersAndRoot_NonRepudiation(
        uint256[] memory publicInputs,
        uint256[] memory nullifiers,
        uint256 piIndex
    ) internal view returns (uint256) {
        // copy input commitments
        for (uint256 i = 0; i < nullifiers.length; i++) {
            publicInputs[piIndex++] = nullifiers[i];
        }
        // copy root
        publicInputs[piIndex++] = _dpnr.root;
        return piIndex;
    }

    function _fillEnablesAndOutputs_NonRepudiation(
        uint256[] memory publicInputs,
        uint256[] memory nullifiers,
        uint256[] memory outputs,
        uint256 piIndex
    ) internal pure returns (uint256) {
        // populate enables
        for (uint256 i = 0; i < nullifiers.length; i++) {
            publicInputs[piIndex++] = (nullifiers[i] == 0) ? 0 : 1;
        }
        // copy output commitments
        for (uint256 i = 0; i < outputs.length; i++) {
            publicInputs[piIndex++] = outputs[i];
        }
        return piIndex;
    }

    function _fillNonceAndArbiter_NonRepudiation(
        uint256[] memory publicInputs,
        uint256 piIndex
    ) internal view {
        // copy encryption nonce
        publicInputs[piIndex++] = _dpnr.encryptionNonce;
        // copy arbiter public key
        publicInputs[piIndex++] = arbiter[0];
        publicInputs[piIndex++] = arbiter[1];
    }
}
