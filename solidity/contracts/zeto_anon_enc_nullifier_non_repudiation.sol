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
    /// @dev Decoded proof payload, kept in storage during a single
    ///      `constructPublicInputs` call so the helper functions used to
    ///      assemble the public-inputs vector don't blow the EVM's
    ///      16-local-variable stack budget.
    struct _DecodedProof_NonRepudiation {
        uint256 root;
        uint256 encryptionNonce;
        uint256[2] ecdhPublicKey;
        uint256[] encryptedValuesForReceiver;
        uint256[] encryptedValuesForAuthority;
    }

    _DecodedProof_NonRepudiation private _dpnr;

    /// @dev The arbiter public key that must be used to encrypt the
    ///      "authority" envelope of every transaction. Configured by the
    ///      contract owner via {setArbiter} and contributed as a public
    ///      input to the transfer circuit so the proof is bound to a
    ///      specific arbiter.
    uint256[2] private arbiter;

    /// @dev Reserved storage to allow new state variables to be added in
    ///      future upgrades of this contract without shifting the storage
    ///      layout of inheriting contracts. `_dpnr` occupies 5 slots
    ///      (root, encryptionNonce, ecdhPublicKey [2 slots], two dynamic
    ///      array head pointers fold into 1 slot each conceptually but
    ///      Solidity reserves 1 slot per `uint256[]`, so 2 more = 5 total)
    ///      and `arbiter` occupies 2, for 7 total state slots.
    uint256[43] private __gap;

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
            _DecodedProof_NonRepudiation memory dp,
            Commonlib.Proof memory proofStruct
        ) = decodeProof_NonRepudiation(proof);

        if (!inputsLocked) {
            validateRoot(dp.root);
        }

        _dpnr = dp;

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

    function _calcSize_NonRepudiation(
        uint256[] memory nullifiers,
        uint256[] memory outputs
    ) internal view returns (uint256) {
        return
            _dpnr.ecdhPublicKey.length +
            _dpnr.encryptedValuesForReceiver.length +
            _dpnr.encryptedValuesForAuthority.length +
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
        for (uint256 i = 0; i < _dpnr.ecdhPublicKey.length; ++i) {
            publicInputs[piIndex++] = _dpnr.ecdhPublicKey[i];
        }
        for (uint256 i = 0; i < _dpnr.encryptedValuesForReceiver.length; ++i) {
            publicInputs[piIndex++] = _dpnr.encryptedValuesForReceiver[i];
        }
        for (uint256 i = 0; i < _dpnr.encryptedValuesForAuthority.length; ++i) {
            publicInputs[piIndex++] = _dpnr.encryptedValuesForAuthority[i];
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
        publicInputs[piIndex++] = _dpnr.root;
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
        publicInputs[piIndex++] = _dpnr.encryptionNonce;
        publicInputs[piIndex++] = arbiter[0];
        publicInputs[piIndex++] = arbiter[1];
    }
}
