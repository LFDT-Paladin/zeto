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

import {Zeto_AnonNullifier} from "./zeto_anon_nullifier.sol";
import {Commonlib} from "./lib/common/common.sol";
import {IZetoInitializable} from "./lib/interfaces/IZetoInitializable.sol";

/// @title A sample implementation of a Zeto based fungible token with
///        anonymity, encryption, and history masking via nullifiers.
/// @author Kaleido, Inc.
/// @notice Decimals: this token uses **4** decimals, inherited from
///         {ZetoCommon.decimals}. Indexers and UIs reading this contract
///         directly should treat balances accordingly.
/// @dev The proof has the following statements:
///        - each value in the output commitments must be a positive number in the range 0 ~ (2\*\*40 - 1)
///        - the sum of the nullified values match the sum of output values
///        - the hashes in the input and output match the hash(value, salt, owner public key) formula
///        - the sender possesses the private BabyJubjub key, whose public key is part of the pre-image of the input commitment hashes, which match the corresponding nullifiers
///        - the encrypted value in the output is derived from the receiver's UTXO value and encrypted with a shared secret using the ECDH protocol between the sender and receiver
///        - the nullifiers represent input commitments that are included in a Sparse Merkle Tree represented by the root hash
contract Zeto_AnonEncNullifier is Zeto_AnonNullifier {
    /// @dev Decoded proof payload, kept in storage during a single
    ///      `constructPublicInputs` call so the helper functions used to
    ///      assemble the public-inputs vector don't blow the EVM's
    ///      16-local-variable stack budget. Reset implicitly on each
    ///      transition because `_dpe` is overwritten by the next
    ///      transaction's decode step before any read.
    struct _DecodedProof_EncNullifier {
        uint256 root;
        uint256 encryptionNonce;
        uint256[2] ecdhPublicKey;
        uint256[] encryptedValues;
    }

    _DecodedProof_EncNullifier private _dpe;

    /// @dev Reserved storage to allow new state variables to be added in
    ///      future upgrades of this contract without shifting the storage
    ///      layout of inheriting contracts (e.g. KYC / non-repudiation
    ///      derivatives). Sized so that `<state slots> + __gap.length == 50`,
    ///      matching the OpenZeppelin upgradeable convention. `_dpe`
    ///      occupies 4 slots (uint256 root, uint256 encryptionNonce,
    ///      uint256[2] ecdhPublicKey -> 2 slots, uint256[] encryptedValues
    ///      head pointer -> 1 slot), so the gap is sized at 46.
    uint256[46] private __gap;

    /// @dev Lock the implementation contract on construction. The parent
    ///      {Zeto_AnonNullifier} already does this via its own constructor
    ///      (which Solidity invokes as part of every leaf's deployment),
    ///      but we restate it here so the H-2 protection survives any
    ///      future refactor that changes the inheritance graph.
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

    /**
     * @dev Layout of `proof` (ABI-encoded tuple):
     *        (uint256 root,
     *         uint256 encryptionNonce,
     *         uint256[2] ecdhPublicKey,
     *         uint256[] encryptedValues,
     *         Commonlib.Proof groth16Proof)
     *
     *      Root validation is performed here whenever inputs are unlocked
     *      so the proof bytes are decoded exactly once per transition
     *      (mirrors the L-4 cleanup applied to {Zeto_AnonNullifier}).
     */
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

        if (!inputsLocked) {
            validateRoot(dp.root);
        }

        _dpe = dp;

        uint256[] memory extra = extraInputs();
        uint256 size = _calcSize_EncNullifier(
            nullifiers,
            outputs,
            extra,
            inputsLocked
        );

        uint256[] memory publicInputs = new uint256[](size);
        _fillPublicInputs_EncNullifier(
            publicInputs,
            nullifiers,
            outputs,
            extra,
            inputsLocked
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
        return (
            _DecodedProof_EncNullifier(
                root,
                encryptionNonce,
                ecdhPublicKey,
                encryptedValues
            ),
            proofStruct
        );
    }

    /// @dev Public-inputs vector size. For unlocked spends the layout is
    ///        ecdhPublicKey ++ encryptedValues ++ nullifiers ++ root
    ///          ++ enabled-flags ++ extra ++ outputs ++ encryptionNonce
    ///      For locked-input spends the nullifier-history (root + flags)
    ///      portion of the witness is absent because locked inputs are
    ///      raw UTXOs, not nullifiers; the encryption commitments and the
    ///      output commitments still apply.
    function _calcSize_EncNullifier(
        uint256[] memory nullifiers,
        uint256[] memory outputs,
        uint256[] memory extra,
        bool inputsLocked
    ) internal view returns (uint256) {
        if (inputsLocked) {
            return
                _dpe.ecdhPublicKey.length +
                _dpe.encryptedValues.length +
                nullifiers.length +
                extra.length +
                outputs.length +
                1; // encryptionNonce
        }
        return
            _dpe.ecdhPublicKey.length +
            _dpe.encryptedValues.length +
            (nullifiers.length * 2) + // nullifiers + enabled flags
            1 + // root
            extra.length +
            outputs.length +
            1; // encryptionNonce
    }

    function _fillPublicInputs_EncNullifier(
        uint256[] memory publicInputs,
        uint256[] memory nullifiers,
        uint256[] memory outputs,
        uint256[] memory extra,
        bool inputsLocked
    ) internal view {
        uint256 piIndex = 0;
        piIndex = _fillEcdhAndEncrypted(publicInputs, piIndex);
        if (!inputsLocked) {
            piIndex = _fillNullifiersAndRoot(publicInputs, nullifiers, piIndex);
            piIndex = _fillEnablesAndExtra(
                publicInputs,
                nullifiers,
                extra,
                piIndex
            );
        } else {
            for (uint256 i = 0; i < nullifiers.length; i++) {
                publicInputs[piIndex++] = nullifiers[i];
            }
            for (uint256 i = 0; i < extra.length; i++) {
                publicInputs[piIndex++] = extra[i];
            }
        }
        _fillOutputsAndNonce(publicInputs, outputs, piIndex);
    }

    function _fillEcdhAndEncrypted(
        uint256[] memory publicInputs,
        uint256 piIndex
    ) internal view returns (uint256) {
        for (uint256 i = 0; i < _dpe.ecdhPublicKey.length; ++i) {
            publicInputs[piIndex++] = _dpe.ecdhPublicKey[i];
        }
        for (uint256 i = 0; i < _dpe.encryptedValues.length; ++i) {
            publicInputs[piIndex++] = _dpe.encryptedValues[i];
        }
        return piIndex;
    }

    function _fillNullifiersAndRoot(
        uint256[] memory publicInputs,
        uint256[] memory nullifiers,
        uint256 piIndex
    ) internal view returns (uint256) {
        for (uint256 i = 0; i < nullifiers.length; i++) {
            publicInputs[piIndex++] = nullifiers[i];
        }
        publicInputs[piIndex++] = _dpe.root;
        return piIndex;
    }

    function _fillEnablesAndExtra(
        uint256[] memory publicInputs,
        uint256[] memory nullifiers,
        uint256[] memory extra,
        uint256 piIndex
    ) internal pure returns (uint256) {
        for (uint256 i = 0; i < nullifiers.length; i++) {
            publicInputs[piIndex++] = (nullifiers[i] == 0) ? 0 : 1;
        }
        for (uint256 i = 0; i < extra.length; i++) {
            publicInputs[piIndex++] = extra[i];
        }
        return piIndex;
    }

    function _fillOutputsAndNonce(
        uint256[] memory publicInputs,
        uint256[] memory outputs,
        uint256 piIndex
    ) internal view {
        for (uint256 i = 0; i < outputs.length; i++) {
            publicInputs[piIndex++] = outputs[i];
        }
        publicInputs[piIndex++] = _dpe.encryptionNonce;
    }

    function extraInputs()
        internal
        view
        virtual
        override
        returns (uint256[] memory)
    {
        return new uint256[](0);
    }
}
