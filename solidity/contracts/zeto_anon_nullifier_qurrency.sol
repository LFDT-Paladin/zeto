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
    /// @dev Decoded proof payload, kept in storage during a single
    ///      `constructPublicInputs` call so the helper functions used to
    ///      assemble the public-inputs vector don't blow the EVM's
    ///      16-local-variable stack budget.
    struct _DecodedProof_Qurrency {
        uint256 root;
        uint256 encryptionNonce;
        uint256[] encryptedValues;
        uint256[25] encapsulatedSharedSecret;
    }

    _DecodedProof_Qurrency private _dpq;
    uint256[] private _publicInputs;
    uint256 private _piIndex;

    /// @dev Reserved storage to allow new state variables to be added in
    ///      future upgrades of this contract. `_dpq` occupies 28 slots
    ///      (root, encryptionNonce, dynamic-array head pointer for
    ///      encryptedValues, plus 25 for the fixed-size
    ///      encapsulatedSharedSecret). `_publicInputs` and `_piIndex`
    ///      add 2 more, for 30 total state slots.
    uint256[20] private __gap;

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
        (_DecodedProof_Qurrency memory dp, ) = decodeProof_Qurrency(proof);
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
            _DecodedProof_Qurrency memory dp,
            Commonlib.Proof memory proofStruct
        ) = decodeProof_Qurrency(proof);

        if (!inputsLocked) {
            validateRoot(dp.root);
        }

        _dpq = dp;

        uint256 size = _calcSize_Qurrency(nullifiers, outputs, inputsLocked);
        _fillPublicInputs_Qurrency(size, nullifiers, outputs, inputsLocked);
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

    function _calcSize_Qurrency(
        uint256[] memory nullifiers,
        uint256[] memory outputs,
        bool inputsLocked
    ) internal view returns (uint256) {
        if (inputsLocked) {
            return
                _dpq.encapsulatedSharedSecret.length +
                _dpq.encryptedValues.length +
                nullifiers.length +
                outputs.length;
        }
        return
            _dpq.encapsulatedSharedSecret.length +
            _dpq.encryptedValues.length +
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
        _publicInputs = new uint256[](size);
        _piIndex = 0;

        _fillEncapsulatedSharedSecret_Q();
        _fillEncryptedValues_Q();
        _fillInputs_Q(nullifiers);
        if (!inputsLocked) {
            _fillRootAndEnables_Q(nullifiers);
        }
        _fillOutputs_Q(outputs);
    }

    function _fillEncapsulatedSharedSecret_Q() internal {
        for (uint256 i = 0; i < _dpq.encapsulatedSharedSecret.length; ++i) {
            _publicInputs[_piIndex++] = _dpq.encapsulatedSharedSecret[i];
        }
    }

    function _fillEncryptedValues_Q() internal {
        for (uint256 i = 0; i < _dpq.encryptedValues.length; ++i) {
            _publicInputs[_piIndex++] = _dpq.encryptedValues[i];
        }
    }

    function _fillInputs_Q(uint256[] memory nullifiers) internal {
        for (uint256 i = 0; i < nullifiers.length; i++) {
            _publicInputs[_piIndex++] = nullifiers[i];
        }
    }

    function _fillRootAndEnables_Q(uint256[] memory nullifiers) internal {
        _publicInputs[_piIndex++] = _dpq.root;
        for (uint256 i = 0; i < nullifiers.length; i++) {
            _publicInputs[_piIndex++] = (nullifiers[i] == 0) ? 0 : 1;
        }
    }

    function _fillOutputs_Q(uint256[] memory outputs) internal {
        for (uint256 i = 0; i < outputs.length; i++) {
            _publicInputs[_piIndex++] = outputs[i];
        }
    }
}
