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

import {IZetoLockableCapability} from "./interfaces/IZetoLockableCapability.sol";
import {Commonlib} from "./common/common.sol";
import {ZetoCommon} from "./zeto_common.sol";

/// @title ZetoLockable
/// @author Kaleido, Inc.
/// @dev Reusable mixin that wires the {IZetoLockableCapability} lock
///      lifecycle on top of {ZetoCommon}, agnostic of whether the
///      embedding token is fungible or non-fungible.
///
///      The mixin owns:
///        * The lock-state mappings ({_locks}, {_txIds},
///          {_utxoDelegates}).
///        * The full create / update / delegate / spend / cancel
///          lifecycle entry points.
///        * The hash-domain separated unlock-commitment helpers.
///        * The {locked(uint256)} override that joins the storage
///          layer's "is locked" bit with the per-UTXO spender
///          projection.
///
///      Descendants are responsible for the two ZK-circuit-specific
///      hooks {_doLockTransition} and {_transferLocked}, which
///      serialize a Zeto state transition into the public-inputs
///      shape expected by their concrete circuit family. Fungible
///      tokens pad inputs/outputs to the next supported batch size
///      via {ZetoCommon.checkAndPadCommitments}; non-fungible tokens
///      operate on fixed 1-in/1-out arrays. Keeping the hooks
///      virtual in this mixin lets both flavours share every other
///      moving piece of the lock lifecycle.
abstract contract ZetoLockable is ZetoCommon, IZetoLockableCapability {
    /// @dev Stored lock state, indexed by lockId.
    struct ZetoLockInfo {
        address owner;
        address spender;
        bytes32 spendCommitment;
        bytes32 cancelCommitment;
        // The locked content: the lockedOutputs from createLock, which
        // become the locked inputs for spendLock/cancelLock.
        uint256[] lockedInputs;
    }

    mapping(bytes32 => ZetoLockInfo) internal _locks;

    /// @dev Replay-protection map for caller-supplied txIds, keyed by
    ///      `(sender, txId)`. Keying by txId alone would let any
    ///      observer of the mempool front-run a victim's lock-lifecycle
    ///      call by submitting a tiny tx that reserves the same global
    ///      txId, causing the victim's tx to revert with
    ///      {DuplicateTransaction}. Per-sender keying preserves replay
    ///      protection for the legitimate caller while making the
    ///      reservation collision-free across senders. Combined with
    ///      `_computeLockId = keccak256(address(this), msg.sender,
    ///      txId)`, this also guarantees lockIds derived from
    ///      {createLock} are globally unique per sender.
    mapping(address => mapping(bytes32 => bool)) internal _txIds;

    /// @dev Per-UTXO spender for any locked UTXO produced by this
    ///      contract.
    ///
    ///      The lock-id-keyed `_locks[lockId].spender` is the source of
    ///      truth for which lock a spender is authorized over; this map
    ///      is a per-UTXO projection of that information so the public
    ///      view {locked(uint256)} can answer
    ///      "(isLocked, currentSpender)" for an arbitrary UTXO in O(1)
    ///      without a UTXO -> lockId reverse index. Kept in sync by
    ///      {_setLockDelegates} (on lock creation, delegation, and any
    ///      new locked outputs produced by a spend) and
    ///      {_clearLockDelegates} (when locked inputs are consumed).
    ///
    ///      Authorization decisions MUST go through {onlySpender} /
    ///      {_locks}, never through this map.
    mapping(uint256 => address) internal _utxoDelegates;

    /// @dev Reserved storage to allow new state variables to be added
    ///      in future upgrades without shifting the storage layout of
    ///      inheriting contracts. Sized at 50 slots, matching the
    ///      OpenZeppelin upgradeable convention. When a new state
    ///      variable is added to ZetoLockable, decrement the gap by the
    ///      equivalent number of slots so descendants' layouts stay
    ///      stable.
    uint256[50] private __gap;

    modifier lockActive(bytes32 lockId) {
        if (_locks[lockId].owner == address(0)) {
            revert LockNotActive(lockId);
        }
        _;
    }

    modifier onlySpender(bytes32 lockId) {
        address spender = _locks[lockId].spender;
        if (spender != msg.sender) {
            revert LockUnauthorized(lockId, spender, msg.sender);
        }
        _;
    }

    function _useTxId(bytes32 txId) internal {
        if (_txIds[msg.sender][txId]) {
            revert DuplicateTransaction(txId);
        }
        _txIds[msg.sender][txId] = true;
    }

    /// @dev Project the lock-level spender onto each UTXO in `utxos`.
    ///      Skips zero-padding entries so it is safe to pass calldata
    ///      arrays straight from the lock payloads.
    function _setLockDelegates(
        uint256[] memory utxos,
        address spender
    ) internal {
        for (uint256 i = 0; i < utxos.length; ++i) {
            if (utxos[i] != 0) {
                _utxoDelegates[utxos[i]] = spender;
            }
        }
    }

    /// @dev Wipe the per-UTXO spender projection for each UTXO in
    ///      `utxos`. Called when a lock's inputs are consumed (spend or
    ///      cancel) so that the public {locked} view returns
    ///      `(false, address(0))` for them immediately, even if some
    ///      future code path were to resurrect the locked-state entry.
    function _clearLockDelegates(uint256[] memory utxos) internal {
        for (uint256 i = 0; i < utxos.length; ++i) {
            if (utxos[i] != 0) {
                delete _utxoDelegates[utxos[i]];
            }
        }
    }

    // ------------------------------------------------------------------
    // ILockableCapability lifecycle
    // ------------------------------------------------------------------

    /// @inheritdoc IZetoLockableCapability
    function computeLockId(
        bytes calldata createArgs
    ) external view override returns (bytes32) {
        ZetoCreateLockArgs memory args = abi.decode(
            createArgs,
            (ZetoCreateLockArgs)
        );
        return _computeLockId(args.txId);
    }

    function _computeLockId(bytes32 txId) internal view returns (bytes32) {
        return keccak256(abi.encode(address(this), msg.sender, txId));
    }

    /// @dev Domain-separation tag for spend-intent commitments.
    ///      Included in {_buildUnlockHash} so that a payload hashing to
    ///      a lock's {ZetoLockInfo.spendCommitment} cannot also hash to
    ///      its {ZetoLockInfo.cancelCommitment}, preventing a spender
    ///      from transposing a spend payload into {cancelLock} (or vice
    ///      versa) when one of the commitments is non-zero.
    bytes32 private constant _SPEND_HASH_DOMAIN =
        keccak256("Zeto.spendCommitment.v1");

    /// @dev Domain-separation tag for cancel-intent commitments. See
    ///      {_SPEND_HASH_DOMAIN} for the rationale.
    bytes32 private constant _CANCEL_HASH_DOMAIN =
        keccak256("Zeto.cancelCommitment.v1");

    /// @inheritdoc IZetoLockableCapability
    function computeSpendHash(
        uint256[] calldata lockedInputs,
        uint256[] calldata lockedOutputs,
        uint256[] calldata outputs,
        bytes calldata data
    ) external pure override returns (bytes32) {
        return
            _buildUnlockHash(
                lockedInputs,
                lockedOutputs,
                outputs,
                data,
                _SPEND_HASH_DOMAIN
            );
    }

    /// @inheritdoc IZetoLockableCapability
    function computeCancelHash(
        uint256[] calldata lockedInputs,
        uint256[] calldata lockedOutputs,
        uint256[] calldata outputs,
        bytes calldata data
    ) external pure override returns (bytes32) {
        return
            _buildUnlockHash(
                lockedInputs,
                lockedOutputs,
                outputs,
                data,
                _CANCEL_HASH_DOMAIN
            );
    }

    /**
     * @dev Create a new lock by spending unlocked inputs and producing
     *      the locked content. See {ILockableCapability.createLock} for
     *      the generic semantics; the Zeto-specific payload is
     *      {ZetoCreateLockArgs}.
     *
     * Emits {LockCreated} (generic) and {ZetoLockCreated}.
     */
    function createLock(
        bytes calldata createArgs,
        bytes32 spendCommitment,
        bytes32 cancelCommitment,
        bytes calldata data
    ) external override returns (bytes32) {
        ZetoCreateLockArgs memory args = abi.decode(
            createArgs,
            (ZetoCreateLockArgs)
        );

        bytes32 lockId = _computeLockId(args.txId);
        if (_locks[lockId].owner != address(0)) {
            revert DuplicateLock(lockId);
        }
        _useTxId(args.txId);

        _doLockTransition(args);

        ZetoLockInfo storage lock = _locks[lockId];
        lock.owner = msg.sender;
        lock.spender = msg.sender;
        lock.spendCommitment = spendCommitment;
        lock.cancelCommitment = cancelCommitment;
        lock.lockedInputs = args.lockedOutputs;

        emit LockCreated(
            lockId,
            msg.sender,
            msg.sender,
            spendCommitment,
            cancelCommitment,
            data
        );
        emit ZetoLockCreated(
            args.txId,
            lockId,
            msg.sender,
            args.inputs,
            args.outputs,
            args.lockedOutputs,
            args.proof,
            data
        );

        return lockId;
    }

    /**
     * @dev Update the spend/cancel commitments on an active,
     *      owner-controlled lock. Mirrors the previous prepareUnlock
     *      flow but with full-update semantics: both commitments are
     *      replaced atomically.
     *
     * Emits {LockUpdated} and {ZetoLockUpdated}.
     */
    function updateLock(
        bytes32 lockId,
        bytes calldata updateArgs,
        bytes32 spendCommitment,
        bytes32 cancelCommitment,
        bytes calldata data
    ) external override lockActive(lockId) {
        ZetoLockInfo storage lock = _locks[lockId];
        // Authorization first, mutability second, so that an
        // unauthorized caller never learns about the lock's mutability
        // state via the revert reason.
        if (msg.sender != lock.owner) {
            revert LockUnauthorized(lockId, lock.spender, msg.sender);
        }
        if (lock.spender != lock.owner) {
            revert LockImmutable(lockId);
        }

        ZetoUpdateLockArgs memory args = abi.decode(
            updateArgs,
            (ZetoUpdateLockArgs)
        );
        _useTxId(args.txId);

        lock.spendCommitment = spendCommitment;
        lock.cancelCommitment = cancelCommitment;

        emit LockUpdated(
            lockId,
            msg.sender,
            spendCommitment,
            cancelCommitment,
            data
        );
        emit ZetoLockUpdated(args.txId, lockId, msg.sender, data);
    }

    /**
     * @dev Delegate spending authority for the lock. The per-UTXO
     *      spender projection used by the public {locked} view is also
     *      moved here so that subsequent observers see the new spender
     *      for every locked input belonging to this lock.
     *
     * Emits {LockDelegated} and {ZetoLockDelegated}.
     */
    function delegateLock(
        bytes32 lockId,
        bytes calldata delegateArgs,
        address newSpender,
        bytes calldata data
    ) external override lockActive(lockId) onlySpender(lockId) {
        ZetoDelegateLockArgs memory args = abi.decode(
            delegateArgs,
            (ZetoDelegateLockArgs)
        );
        _useTxId(args.txId);

        ZetoLockInfo storage lock = _locks[lockId];
        address previousSpender = lock.spender;
        lock.spender = newSpender;

        _setLockDelegates(lock.lockedInputs, newSpender);

        emit LockDelegated(lockId, previousSpender, newSpender, data);
        emit ZetoLockDelegated(
            args.txId,
            lockId,
            previousSpender,
            newSpender,
            data
        );
    }

    /**
     * @dev Spend the lock by executing the committed unlock operation.
     *      If `spendCommitment` is non-zero, the supplied spendArgs MUST
     *      hash to it.
     *
     * Emits {LockSpent} and {ZetoLockSpent}.
     */
    function spendLock(
        bytes32 lockId,
        bytes calldata spendArgs,
        bytes calldata data
    ) external virtual override lockActive(lockId) onlySpender(lockId) {
        ZetoSpendLockArgs memory args = abi.decode(
            spendArgs,
            (ZetoSpendLockArgs)
        );

        // Snapshot the locked content from storage. The caller is
        // intentionally not allowed to substitute a different set of
        // locked inputs.
        uint256[] memory lockedInputs = _locks[lockId].lockedInputs;
        bytes32 expectedHash = _locks[lockId].spendCommitment;
        _consumeLock(
            lockId,
            lockedInputs,
            expectedHash,
            _SPEND_HASH_DOMAIN,
            args
        );

        emit LockSpent(lockId, msg.sender, data);
        emit ZetoLockSpent(
            args.txId,
            lockId,
            msg.sender,
            lockedInputs,
            args.lockedOutputs,
            args.outputs,
            args.proof,
            data
        );
    }

    /**
     * @dev Cancel the lock by executing the committed cancellation
     *      operation. If `cancelCommitment` is non-zero, the supplied
     *      cancelArgs MUST hash to it.
     *
     * Emits {LockCancelled} and {ZetoLockCancelled}.
     */
    function cancelLock(
        bytes32 lockId,
        bytes calldata cancelArgs,
        bytes calldata data
    ) external virtual override lockActive(lockId) onlySpender(lockId) {
        ZetoSpendLockArgs memory args = abi.decode(
            cancelArgs,
            (ZetoSpendLockArgs)
        );

        uint256[] memory lockedInputs = _locks[lockId].lockedInputs;
        bytes32 expectedHash = _locks[lockId].cancelCommitment;
        _consumeLock(
            lockId,
            lockedInputs,
            expectedHash,
            _CANCEL_HASH_DOMAIN,
            args
        );

        emit LockCancelled(lockId, msg.sender, data);
        emit ZetoLockCancelled(
            args.txId,
            lockId,
            msg.sender,
            lockedInputs,
            args.lockedOutputs,
            args.outputs,
            args.proof,
            data
        );
    }

    // ------------------------------------------------------------------
    // ILockableCapability views
    // ------------------------------------------------------------------

    function getLock(
        bytes32 lockId
    ) external view override lockActive(lockId) returns (LockInfo memory) {
        ZetoLockInfo storage lock = _locks[lockId];
        return
            LockInfo({
                owner: lock.owner,
                spender: lock.spender,
                spendCommitment: lock.spendCommitment,
                cancelCommitment: lock.cancelCommitment
            });
    }

    function isLockActive(
        bytes32 lockId
    ) external view override returns (bool) {
        return _locks[lockId].owner != address(0);
    }

    function getLockContent(
        bytes32 lockId
    ) external view override lockActive(lockId) returns (bytes memory content) {
        return abi.encode(_locks[lockId].lockedInputs);
    }

    /// @inheritdoc IZetoLockableCapability
    function getLockedInputs(
        bytes32 lockId
    )
        external
        view
        override
        lockActive(lockId)
        returns (uint256[] memory lockedInputs)
    {
        return _locks[lockId].lockedInputs;
    }

    /**
     * @dev Override of {ZetoCommon.locked} that fills in the per-UTXO
     *      spender from the {_utxoDelegates} projection. The storage
     *      layer only tells us "is this locked"; the spender lives at
     *      this layer because the lock model itself does.
     *
     *      Returns `(false, address(0))` for any UTXO that is not
     *      currently locked-unspent, including UTXOs whose lock has
     *      been spent or cancelled (since both the storage layer's
     *      locked-set is cleared and `_utxoDelegates[X]` is wiped in
     *      the consume path).
     */
    function locked(uint256 utxo) public view override returns (bool, address) {
        if (!_storage.locked(utxo)) {
            return (false, address(0));
        }
        return (true, _utxoDelegates[utxo]);
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    /**
     * @dev Verify the ZK proof authorizing a {createLock} call and
     *      apply the resulting state transition. Implementations differ
     *      between fungible (padding to the next supported batch size)
     *      and non-fungible (fixed 1-in/1-out) tokens, so this hook is
     *      left abstract. They MUST:
     *
     *        1. {validateTransactionProposal}(args.inputs, args.outputs,
     *           args.lockedOutputs, args.proof, false).
     *        2. {constructPublicInputs}(...) and
     *           {verifyProof}(...) for the unlocked-inputs flavour.
     *        3. {processInputsAndOutputs}(args.inputs, args.outputs,
     *           false).
     *        4. {processLockedOutputs}(args.lockedOutputs).
     *        5. {_setLockDelegates}(args.lockedOutputs, msg.sender).
     */
    function _doLockTransition(ZetoCreateLockArgs memory args) internal virtual;

    /**
     * @dev Apply the ZK-verified state transition that consumes a
     *      lock's `lockedInputs`. See {_doLockTransition} for the
     *      rationale for keeping this abstract.
     */
    function _transferLocked(
        bytes32 lockId,
        uint256[] memory lockedInputs,
        uint256[] memory lockedOutputs,
        uint256[] memory outputs,
        bytes memory proof,
        bytes memory data
    ) internal virtual;

    /**
     * @dev Consume an active lock.
     *
     *      `lockedInputs` MUST be the lock's storage-pinned content
     *      (read by the caller from `_locks[lockId].lockedInputs`). The
     *      spender does not get to choose which UTXOs are consumed: that
     *      decision was made at {createLock} time. This is what makes
     *      "spending lock A consumes lock A's UTXOs" a hard contract
     *      invariant.
     */
    function _consumeLock(
        bytes32 lockId,
        uint256[] memory lockedInputs,
        bytes32 expectedHash,
        bytes32 hashDomain,
        ZetoSpendLockArgs memory args
    ) internal {
        _useTxId(args.txId);

        if (expectedHash != 0) {
            bytes32 actualHash = _buildUnlockHash(
                lockedInputs,
                args.lockedOutputs,
                args.outputs,
                args.data,
                hashDomain
            );
            if (actualHash != expectedHash) {
                revert InvalidUnlockHash(expectedHash, actualHash);
            }
        }

        // Tear down all lock-spender state BEFORE performing the state
        // transition, so any reentrant lookup observes both
        // `_locks[lockId]` and the per-UTXO `_utxoDelegates` projection
        // as cleared.
        _clearLockDelegates(lockedInputs);
        delete _locks[lockId];

        _transferLocked(
            lockId,
            lockedInputs,
            args.lockedOutputs,
            args.outputs,
            args.proof,
            args.data
        );
    }

    /// @dev Build the unlock hash committed to by
    ///      {ZetoLockInfo.spendCommitment} or
    ///      {ZetoLockInfo.cancelCommitment}. `domain` is a per-intent
    ///      separation tag (see {_SPEND_HASH_DOMAIN} /
    ///      {_CANCEL_HASH_DOMAIN}) so that the two commitments live in
    ///      disjoint hash spaces.
    ///
    ///      Each variable-length component is hashed as
    ///      `abi.encode(...)` rather than `abi.encodePacked(...)` to
    ///      avoid the cross-array length-ambiguity that `encodePacked`
    ///      introduces for dynamic arguments (e.g. `[1, 2]` and `[12]`
    ///      collide under `encodePacked` but not under `encode`).
    function _buildUnlockHash(
        uint256[] memory lockedInputs,
        uint256[] memory lockedOutputs,
        uint256[] memory outputs,
        bytes memory data,
        bytes32 domain
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    domain,
                    keccak256(abi.encode(lockedInputs)),
                    keccak256(abi.encode(lockedOutputs)),
                    keccak256(abi.encode(outputs)),
                    keccak256(data)
                )
            );
    }
}
