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

import {ILockableCapability} from "./ILockableCapability.sol";

/**
 * @title IZetoLockableCapability
 * @dev Zeto-specific extension of {ILockableCapability}.
 *
 *      Defines the canonical ABI-encoded payloads (`*Args` parameters) and the
 *      Zeto-specific events emitted alongside the generic ILockableCapability
 *      events, mirroring the pattern used by the noto domain in Paladin.
 *
 *      The lockId is generated deterministically as
 *      `keccak256(abi.encode(address(this), msg.sender, args.txId))` and can be
 *      predicted via {computeLockId} before calling {createLock}.
 */
interface IZetoLockableCapability is ILockableCapability {
    // ----------------------------------------------------------------------
    // Errors retained from the previous IZetoLockable interface
    // ----------------------------------------------------------------------

    /// @dev Thrown when a UTXO is already locked at the storage layer.
    error AlreadyLocked(uint256 utxo);

    /// @dev Thrown when a UTXO is referenced as locked input but is not locked.
    error NotLocked(uint256 utxo);

    /// @dev Thrown when the caller is not the current per-UTXO storage delegate.
    error NotLockDelegate(
        uint256 utxo,
        address currentDelegate,
        address sender
    );

    /// @dev Thrown when a provided spend/cancel payload does not hash to the
    ///      previously committed value.
    error InvalidUnlockHash(bytes32 expected, bytes32 actual);

    /// @dev Thrown when the caller-supplied txId has already been used.
    error DuplicateTransaction(bytes32 txId);

    /// @dev Thrown when computeLockId would collide with an already-active lock.
    error DuplicateLock(bytes32 lockId);

    // ----------------------------------------------------------------------
    // ABI-encoded argument payloads carried by the generic *Args parameters
    // ----------------------------------------------------------------------

    /**
     * @dev Payload for {ILockableCapability.createLock}.createArgs.
     *
     *      The transaction consumes `inputs` (regular UTXOs/nullifiers) and
     *      produces `outputs` (regular UTXOs) and `lockedOutputs` (the locked
     *      content held under the lock). `proof` is the ZK proof authorising
     *      the state transition.
     */
    struct ZetoCreateLockArgs {
        bytes32 txId;
        uint256[] inputs;
        uint256[] outputs;
        uint256[] lockedOutputs;
        bytes proof;
    }

    /**
     * @dev Payload for {ILockableCapability.updateLock}.updateArgs.
     *
     *      Update is metadata-only on Zeto (it rewrites the spend/cancel
     *      commitments), so only a fresh txId is required.
     */
    struct ZetoUpdateLockArgs {
        bytes32 txId;
    }

    /**
     * @dev Payload for {ILockableCapability.delegateLock}.delegateArgs.
     */
    struct ZetoDelegateLockArgs {
        bytes32 txId;
    }

    /**
     * @dev Payload for {ILockableCapability.spendLock}.spendArgs and
     *      {ILockableCapability.cancelLock}.cancelArgs.
     *
     *      The set of locked UTXOs being consumed is intentionally NOT carried
     *      here: it is taken verbatim from the lock's storage-pinned content
     *      (see {getLockContent}) so that "spending lock A always consumes lock
     *      A's UTXOs" is a hard contract invariant rather than a soft hash
     *      check. The {InvalidUnlockHash} check is therefore computed over
     *      `(lock.lockedInputs, lockedOutputs, outputs, data)` where
     *      `lock.lockedInputs` is read from storage.
     */
    struct ZetoSpendLockArgs {
        bytes32 txId;
        uint256[] lockedOutputs;
        uint256[] outputs;
        bytes proof;
        bytes data;
    }

    // ----------------------------------------------------------------------
    // Zeto-specific events emitted alongside the generic events
    // ----------------------------------------------------------------------

    /// @dev Emitted alongside {LockCreated} with decoded Zeto parameters.
    event ZetoLockCreated(
        bytes32 indexed txId,
        bytes32 indexed lockId,
        address indexed owner,
        uint256[] inputs,
        uint256[] outputs,
        uint256[] lockedOutputs,
        bytes proof,
        bytes data
    );

    /// @dev Emitted alongside {LockUpdated} with the Zeto txId.
    event ZetoLockUpdated(
        bytes32 indexed txId,
        bytes32 indexed lockId,
        address indexed owner,
        bytes data
    );

    /// @dev Emitted alongside {LockDelegated} with the Zeto txId.
    event ZetoLockDelegated(
        bytes32 indexed txId,
        bytes32 indexed lockId,
        address indexed from,
        address to,
        bytes data
    );

    /// @dev Emitted alongside {LockSpent} with decoded Zeto parameters.
    ///      `lockedInputs` is the lock's storage-pinned content, not a
    ///      caller-supplied value (see {ZetoSpendLockArgs}).
    event ZetoLockSpent(
        bytes32 indexed txId,
        bytes32 indexed lockId,
        address indexed spender,
        uint256[] lockedInputs,
        uint256[] lockedOutputs,
        uint256[] outputs,
        bytes proof,
        bytes data
    );

    /// @dev Emitted alongside {LockCancelled} with decoded Zeto parameters.
    ///      `lockedInputs` is the lock's storage-pinned content, not a
    ///      caller-supplied value (see {ZetoSpendLockArgs}).
    event ZetoLockCancelled(
        bytes32 indexed txId,
        bytes32 indexed lockId,
        address indexed spender,
        uint256[] lockedInputs,
        uint256[] lockedOutputs,
        uint256[] outputs,
        bytes proof,
        bytes data
    );

    // ----------------------------------------------------------------------
    // Zeto-specific view helpers
    // ----------------------------------------------------------------------

    /**
     * @dev Compute the lockId that {createLock} would generate for a given
     *      caller and createArgs payload. Useful for off-chain pre-computation.
     *
     * @param createArgs ABI-encoded {ZetoCreateLockArgs}.
     * @return lockId    The lockId that would be assigned.
     */
    function computeLockId(
        bytes calldata createArgs
    ) external view returns (bytes32 lockId);

    /**
     * @dev Compute the unlock hash used as the spend/cancel commitment for a
     *      prospective {ZetoSpendLockArgs} payload.
     */
    function computeUnlockHash(
        uint256[] calldata lockedInputs,
        uint256[] calldata lockedOutputs,
        uint256[] calldata outputs,
        bytes calldata data
    ) external pure returns (bytes32);
}
