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

import {Commonlib} from "./lib/common/common.sol";
import {IZetoInitializable} from "./lib/interfaces/IZetoInitializable.sol";
import {Zeto_AnonNullifier} from "./zeto_anon_nullifier.sol";

/// @title A sample implementation of a Zeto based fungible token with
///        anonymity, history masking via nullifiers, and post-quantum
///        ML-KEM encryption envelopes for transferred values.
/// @author Kaleido, Inc.
/// @notice Decimals: this token uses **4** decimals, inherited from
///         {ZetoCommon.decimals}. Indexers and UIs reading this contract
///         directly should treat balances accordingly.
/// @dev Replaces the BabyJubjub-based ECDH envelope used by
///      {Zeto_AnonEncNullifier} with an ML-KEM (post-quantum)
///      key-encapsulation envelope. The proof carries the
///      `encapsulatedSharedSecret` (25 field elements -- the encoded
///      KEM ciphertext) alongside the encrypted output values; the
///      circuit asserts that the encrypted values were produced under
///      the same shared secret derived from that ciphertext.
///
///      Locked-input circuit binding: this contract intentionally does
///      NOT include `msg.sender` in the public-input vector for the
///      locked-input flavour, even though `main` did. Lock-spender
///      authorization is now enforced at the Zeto contract layer (via
///      `ZetoFungible._locks[lockId].spender == msg.sender`) rather than
///      inside the circuit. This matches how {Zeto_AnonNullifier}
///      organises its locked-input proof; deployments that still want a
///      circuit-level binding to the spender can override
///      {constructPublicInputs} and append it.
contract Zeto_AnonNullifierQurrency is Zeto_AnonNullifier {
    /// @dev Proof decode + public-input assembly scratch lives in
    ///      {ZetoAnonNullifierQurrencyStorage} (ERC-7201).

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
    ) public override initializer {
        __ZetoAnonNullifier_init(name, symbol, initialOwner, verifiers);
    }

    function emitTransferEvent(
        uint256[] memory nullifiers,
        uint256[] memory outputs,
        bytes memory proof,
        bytes memory data
    ) internal override {
        ZetoAnonNullifierQurrencyStorage.DecodedProofQurrency memory dp;
        (dp, ) = decodeProof_Qurrency(proof);
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

    /**
     * @dev Layout of `proof` (ABI-encoded tuple):
     *        (uint256 root,
     *         uint256 encryptionNonce,
     *         uint256[] encryptedValues,
     *         uint256[25] encapsulatedSharedSecret,
     *         Commonlib.Proof groth16Proof)
     *
     *      Public-inputs layout (unlocked):
     *        encapsulatedSharedSecret[25]
     *          ++ encryptedValues
     *          ++ nullifiers
     *          ++ root
     *          ++ enabled-flags
     *          ++ outputs
     *
     *      Locked variant drops the `root`/`enabled-flags` block (locked
     *      inputs are raw UTXOs, not nullifiers, so the SMT-membership
     *      block is not part of the witness) but keeps the encryption
     *      commitments so the receiver can still decrypt the new outputs.
     *
     *      Root validation is performed here for the unlocked path so the
     *      proof bytes are decoded exactly once per transition.
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
            ZetoAnonNullifierQurrencyStorage.DecodedProofQurrency memory dp,
            Commonlib.Proof memory proofStruct
        ) = decodeProof_Qurrency(proof);

        if (!inputsLocked) {
            validateRoot(dp.root);
        }

        ZetoAnonNullifierQurrencyStorage.layout().dpq = dp;

        uint256 size = _calcSize_Qurrency(nullifiers, outputs, inputsLocked);
        _fillPublicInputs_Qurrency(size, nullifiers, outputs, inputsLocked);

        ZetoAnonNullifierQurrencyStorage.Layout storage $ = ZetoAnonNullifierQurrencyStorage
            .layout();
        uint256[] memory out = new uint256[]($.publicInputsBuf.length);
        for (uint256 i = 0; i < out.length; ++i) {
            out[i] = $.publicInputsBuf[i];
        }
        return (out, proofStruct);
    }

    function decodeProof_Qurrency(
        bytes memory proof
    )
        internal
        pure
        returns (
            ZetoAnonNullifierQurrencyStorage.DecodedProofQurrency memory dp,
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

    function _calcSize_Qurrency(
        uint256[] memory nullifiers,
        uint256[] memory outputs,
        bool inputsLocked
    ) internal view returns (uint256) {
        ZetoAnonNullifierQurrencyStorage.DecodedProofQurrency storage dq = ZetoAnonNullifierQurrencyStorage
            .layout()
            .dpq;
        if (inputsLocked) {
            return
                dq.encapsulatedSharedSecret.length +
                dq.encryptedValues.length +
                nullifiers.length +
                outputs.length;
        }
        return
            dq.encapsulatedSharedSecret.length +
            dq.encryptedValues.length +
            (nullifiers.length * 2) + // nullifiers + enabled flags
            1 + // root
            outputs.length;
    }

    function _fillPublicInputs_Qurrency(
        uint256 size,
        uint256[] memory nullifiers,
        uint256[] memory outputs,
        bool inputsLocked
    ) internal {
        ZetoAnonNullifierQurrencyStorage.Layout storage $ = ZetoAnonNullifierQurrencyStorage
            .layout();
        $.publicInputsBuf = new uint256[](size);
        $.piIndex = 0;

        _fillEncapsulatedSharedSecret_Q();
        _fillEncryptedValues_Q();
        _fillInputs_Q(nullifiers);
        if (!inputsLocked) {
            _fillRootAndEnables_Q(nullifiers);
        }
        _fillOutputs_Q(outputs);
    }

    function _fillEncapsulatedSharedSecret_Q() internal {
        ZetoAnonNullifierQurrencyStorage.Layout storage $ = ZetoAnonNullifierQurrencyStorage
            .layout();
        for (
            uint256 i = 0;
            i < $.dpq.encapsulatedSharedSecret.length;
            ++i
        ) {
            $.publicInputsBuf[$.piIndex++] = $.dpq.encapsulatedSharedSecret[i];
        }
    }

    function _fillEncryptedValues_Q() internal {
        ZetoAnonNullifierQurrencyStorage.Layout storage $ = ZetoAnonNullifierQurrencyStorage
            .layout();
        for (uint256 i = 0; i < $.dpq.encryptedValues.length; ++i) {
            $.publicInputsBuf[$.piIndex++] = $.dpq.encryptedValues[i];
        }
    }

    function _fillInputs_Q(uint256[] memory nullifiers) internal {
        ZetoAnonNullifierQurrencyStorage.Layout storage $ = ZetoAnonNullifierQurrencyStorage
            .layout();
        for (uint256 i = 0; i < nullifiers.length; i++) {
            $.publicInputsBuf[$.piIndex++] = nullifiers[i];
        }
    }

    function _fillRootAndEnables_Q(uint256[] memory nullifiers) internal {
        ZetoAnonNullifierQurrencyStorage.Layout storage $ = ZetoAnonNullifierQurrencyStorage
            .layout();
        $.publicInputsBuf[$.piIndex++] = $.dpq.root;
        for (uint256 i = 0; i < nullifiers.length; i++) {
            $.publicInputsBuf[$.piIndex++] = (nullifiers[i] == 0) ? 0 : 1;
        }
    }

    function _fillOutputs_Q(uint256[] memory outputs) internal {
        ZetoAnonNullifierQurrencyStorage.Layout storage $ = ZetoAnonNullifierQurrencyStorage
            .layout();
        for (uint256 i = 0; i < outputs.length; i++) {
            $.publicInputsBuf[$.piIndex++] = outputs[i];
        }
    }
}

/// @dev ERC-7201 (`erc7201:zeto.storage.Zeto_AnonNullifierQurrency`).
library ZetoAnonNullifierQurrencyStorage {
    struct DecodedProofQurrency {
        uint256 root;
        uint256 encryptionNonce;
        uint256[] encryptedValues;
        uint256[25] encapsulatedSharedSecret;
    }

    struct Layout {
        DecodedProofQurrency dpq;
        uint256[] publicInputsBuf;
        uint256 piIndex;
    }

    bytes32 private constant STORAGE_LOCATION =
        0x61ea13f87e8d672de1c36df013aa52a47bae99190f6e222ce275d312c118d800;

    function layout() internal pure returns (Layout storage $) {
        assembly {
            $.slot := STORAGE_LOCATION
        }
    }
}
