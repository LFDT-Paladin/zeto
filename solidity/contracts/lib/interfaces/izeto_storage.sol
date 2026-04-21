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

interface IZetoStorage {
    enum UTXOStatus {
        UNKNOWN, // default value for the empty UTXO slots
        UNSPENT,
        SPENT
    }

    // For the main UTXO storage

    /**
     * @dev query whether a UTXO is currently spent
     * @param txo The UTXO to check
     * @return bool whether the UTXO is spent
     */
    function spent(uint256 txo) external view returns (UTXOStatus);

    /**
     * @dev validate the inputs
     * @param inputs The inputs to validate
     * @param inputsLocked Whether the inputs are locked
     */
    function validateInputs(
        uint256[] calldata inputs,
        bool inputsLocked
    ) external view;

    /**
     * @dev validate the outputs
     * @param outputs The outputs to validate
     */
    function validateOutputs(uint256[] calldata outputs) external view;

    /**
     * @dev validate the root
     * @param root The root to validate
     * @return bool whether the root is valid
     */
    function validateRoot(uint256 root) external view returns (bool);

    /**
     * @dev get the root
     * @return uint256 the root
     */
    function getRoot() external view returns (uint256);

    /**
     * @dev process the inputs
     * @param inputs The inputs to process
     * @param inputsLocked Whether the inputs are locked
     */
    function processInputs(
        uint256[] calldata inputs,
        bool inputsLocked
    ) external;

    /**
     * @dev process the outputs
     * @param outputs The outputs to process
     */
    function processOutputs(uint256[] calldata outputs) external;

    /**
     * @dev Register freshly-minted locked UTXOs in the locked-UTXO ledger.
     *
     *      The storage layer is intentionally a thin UTXO substrate and
     *      does NOT track who is allowed to spend a locked UTXO; that
     *      responsibility belongs to the Zeto contract on top (e.g. the
     *      lock-id-keyed `_locks[lockId].spender` in
     *      `ZetoFungible`-style lockable-capability contracts). Callers
     *      that need delegate/spender semantics must maintain that state
     *      themselves above this interface.
     *
     * @param lockedOutputs The locked UTXOs to register as UNSPENT
     */
    function processLockedOutputs(uint256[] calldata lockedOutputs) external;

    /**
     * @dev Query whether a UTXO is currently in the locked-unspent set.
     *
     *      The delegate / spender of the lock is intentionally NOT
     *      returned here: the storage layer no longer tracks it. To
     *      surface the spender alongside the locked-state, expose the
     *      combined view at the Zeto layer instead.
     *
     * @param utxo The UTXO to check
     * @return whether the UTXO is currently locked-unspent
     */
    function locked(uint256 utxo) external view returns (bool);
}
