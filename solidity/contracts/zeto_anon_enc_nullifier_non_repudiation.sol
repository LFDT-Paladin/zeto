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

import {Commonlib} from "./lib/common/common.sol";
import {IZetoInitializable} from "./lib/interfaces/IZetoInitializable.sol";
import {Zeto_AnonEncNullifier} from "./zeto_anon_enc_nullifier.sol";

/// @title A sample implementation of a Zeto based fungible token with
///        anonymity, encryption, history masking via nullifiers, and
///        non-repudiation through arbiter-decryptable transfer envelopes.
/// @author Kaleido, Inc.
/// @notice Decimals: this token uses **4** decimals, inherited from
///         {ZetoCommon.decimals}. Indexers and UIs reading this contract
///         directly should treat balances accordingly.
/// @dev Adds a second encryption envelope (the "authority" envelope) on
///      top of {Zeto_AnonEncNullifier}, encrypted to the configured
///      arbiter's BabyJubjub public key. The transfer ZK circuit asserts
///      that the same plaintext is encrypted to both the receiver and the
///      arbiter, so the arbiter can later decrypt every transfer envelope
///      it observes on-chain. This is what gives the contract its
///      non-repudiation property: the sender cannot later deny the
///      contents of a transfer to the arbiter.
contract Zeto_AnonEncNullifierNonRepudiation is Zeto_AnonEncNullifier {
    /// @dev Non-repudiation-specific state ({ZetoAnonEncNullifierNonRepudiationStorage}, ERC-7201).

    /// @dev Per-contract event for non-repudiable transfers. Carries both
    ///      the receiver-bound encryption envelope and the
    ///      authority-bound envelope, alongside the ECDH public key and
    ///      nonce required to decrypt them.
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

    /// @dev Lock the implementation contract on construction. Restated at
    ///      every leaf in the inheritance graph for H-2 robustness.
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

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
        ZetoAnonEncNullifierNonRepudiationStorage.layout().arbiter = _arbiter;
    }

    function getArbiter() public view returns (uint256[2] memory) {
        uint256[2] storage a = ZetoAnonEncNullifierNonRepudiationStorage.layout()
            .arbiter;
        return [a[0], a[1]];
    }

    function emitTransferEvent(
        uint256[] memory nullifiers,
        uint256[] memory outputs,
        bytes memory proof,
        bytes memory data
    ) internal override {
        ZetoAnonEncNullifierNonRepudiationStorage.DecodedProofNonRepudiation
            memory dp;
        (dp, ) = decodeProof_NonRepudiation(proof);
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

    /**
     * @dev Layout of `proof` (ABI-encoded tuple):
     *        (uint256 root,
     *         uint256 encryptionNonce,
     *         uint256[2] ecdhPublicKey,
     *         uint256[] encryptedValuesForReceiver,
     *         uint256[] encryptedValuesForAuthority,
     *         Commonlib.Proof groth16Proof)
     *
     *      Public-inputs layout:
     *        ecdhPublicKey
     *          ++ encryptedValuesForReceiver
     *          ++ encryptedValuesForAuthority
     *          ++ nullifiers
     *          ++ root
     *          ++ enabled-flags
     *          ++ outputs
     *          ++ encryptionNonce
     *          ++ arbiter
     *
     *      Root validation is performed here for the unlocked path so the
     *      proof bytes are decoded exactly once per transition.
     */
    function constructPublicInputs(
        uint256[] memory nullifiers,
        uint256[] memory outputs,
        bytes memory proof,
        bool inputsLocked
    ) internal override returns (uint256[] memory, Commonlib.Proof memory) {
        (
            ZetoAnonEncNullifierNonRepudiationStorage.DecodedProofNonRepudiation
                memory dp,
            Commonlib.Proof memory proofStruct
        ) = decodeProof_NonRepudiation(proof);

        if (!inputsLocked) {
            validateRoot(dp.root);
        }

        ZetoAnonEncNullifierNonRepudiationStorage.layout().dpnr = dp;

        uint256 size = _calcSize_NonRepudiation(nullifiers, outputs);
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
            ZetoAnonEncNullifierNonRepudiationStorage.DecodedProofNonRepudiation
                memory dp,
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

    function _calcSize_NonRepudiation(
        uint256[] memory nullifiers,
        uint256[] memory outputs
    ) internal view returns (uint256) {
        return
            ZetoAnonEncNullifierNonRepudiationStorage.layout().dpnr.ecdhPublicKey.length +
            ZetoAnonEncNullifierNonRepudiationStorage.layout().dpnr.encryptedValuesForReceiver.length +
            ZetoAnonEncNullifierNonRepudiationStorage.layout().dpnr.encryptedValuesForAuthority.length +
            (nullifiers.length * 2) + // nullifiers + enabled flags
            outputs.length +
            2 + // root + encryptionNonce
            2; // arbiter public key
    }

    function _fillPublicInputs_NonRepudiation(
        uint256[] memory publicInputs,
        uint256[] memory nullifiers,
        uint256[] memory outputs
    ) internal view {
        uint256 piIndex = 0;
        piIndex = _fillEcdhAndEncrypted_NR(publicInputs, piIndex);
        piIndex = _fillNullifiersAndRoot_NR(publicInputs, nullifiers, piIndex);
        piIndex = _fillEnablesAndOutputs_NR(
            publicInputs,
            nullifiers,
            outputs,
            piIndex
        );
        _fillNonceAndArbiter_NR(publicInputs, piIndex);
    }

    function _fillEcdhAndEncrypted_NR(
        uint256[] memory publicInputs,
        uint256 piIndex
    ) internal view returns (uint256) {
        for (uint256 i = 0; i < ZetoAnonEncNullifierNonRepudiationStorage.layout().dpnr.ecdhPublicKey.length; ++i) {
            publicInputs[piIndex++] = ZetoAnonEncNullifierNonRepudiationStorage.layout().dpnr.ecdhPublicKey[i];
        }
        for (uint256 i = 0; i < ZetoAnonEncNullifierNonRepudiationStorage.layout().dpnr.encryptedValuesForReceiver.length; ++i) {
            publicInputs[piIndex++] = ZetoAnonEncNullifierNonRepudiationStorage.layout().dpnr.encryptedValuesForReceiver[i];
        }
        for (uint256 i = 0; i < ZetoAnonEncNullifierNonRepudiationStorage.layout().dpnr.encryptedValuesForAuthority.length; ++i) {
            publicInputs[piIndex++] = ZetoAnonEncNullifierNonRepudiationStorage.layout().dpnr.encryptedValuesForAuthority[i];
        }
        return piIndex;
    }

    function _fillNullifiersAndRoot_NR(
        uint256[] memory publicInputs,
        uint256[] memory nullifiers,
        uint256 piIndex
    ) internal view returns (uint256) {
        for (uint256 i = 0; i < nullifiers.length; i++) {
            publicInputs[piIndex++] = nullifiers[i];
        }
        publicInputs[piIndex++] = ZetoAnonEncNullifierNonRepudiationStorage.layout().dpnr.root;
        return piIndex;
    }

    function _fillEnablesAndOutputs_NR(
        uint256[] memory publicInputs,
        uint256[] memory nullifiers,
        uint256[] memory outputs,
        uint256 piIndex
    ) internal pure returns (uint256) {
        for (uint256 i = 0; i < nullifiers.length; i++) {
            publicInputs[piIndex++] = (nullifiers[i] == 0) ? 0 : 1;
        }
        for (uint256 i = 0; i < outputs.length; i++) {
            publicInputs[piIndex++] = outputs[i];
        }
        return piIndex;
    }

    function _fillNonceAndArbiter_NR(
        uint256[] memory publicInputs,
        uint256 piIndex
    ) internal view {
        publicInputs[piIndex++] = ZetoAnonEncNullifierNonRepudiationStorage.layout().dpnr.encryptionNonce;
        uint256[2] storage arb = ZetoAnonEncNullifierNonRepudiationStorage.layout()
            .arbiter;
        publicInputs[piIndex++] = arb[0];
        publicInputs[piIndex++] = arb[1];
    }
}

/// @dev ERC-7201 (`erc7201:zeto.storage.Zeto_AnonEncNullifierNonRepudiation`).
library ZetoAnonEncNullifierNonRepudiationStorage {
    struct DecodedProofNonRepudiation {
        uint256 root;
        uint256 encryptionNonce;
        uint256[2] ecdhPublicKey;
        uint256[] encryptedValuesForReceiver;
        uint256[] encryptedValuesForAuthority;
    }

    struct Layout {
        DecodedProofNonRepudiation dpnr;
        uint256[2] arbiter;
    }

    bytes32 private constant STORAGE_LOCATION =
        0x077d29c08c3f481ec46575d42e52007dfbbb47114226730e96bb8e7b43c49600;

    function layout() internal pure returns (Layout storage $) {
        assembly {
            $.slot := STORAGE_LOCATION
        }
    }
}
