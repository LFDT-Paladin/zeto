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

import {IGroth16Verifier} from "./interfaces/izeto_verifier.sol";
import {IZetoInitializable} from "./interfaces/izeto_initializable.sol";
import {IZetoLockableCapability} from "./interfaces/IZetoLockableCapability.sol";
import {Commonlib} from "./common/common.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {ZetoCommon} from "./zeto_common.sol";
import {IZetoStorage} from "./interfaces/izeto_storage.sol";

/// @title A sample implementation of a base Zeto fungible token contract
/// @author Kaleido, Inc.
/// @dev Defines the verifier library for checking UTXOs against a claimed value.
///      Implements {IZetoLockableCapability} (which extends ILockableCapability)
///      to provide the create/update/delegate/spend/cancel lock lifecycle.
///
///      Inherits {ReentrancyGuardUpgradeable} so that {deposit} and {withdraw},
///      which perform external ERC20 transfers, are protected from reentrant
///      calls (defense-in-depth on top of the checks-effects-interactions
///      ordering enforced inside those functions).
abstract contract ZetoFungible is
    ZetoCommon,
    ReentrancyGuardUpgradeable,
    IZetoLockableCapability
{
    // _depositVerifier library for checking UTXOs against a claimed value.
    // this can be used in the optional deposit calls to verify that
    // the UTXOs match the deposited value
    IGroth16Verifier internal _depositVerifier;
    // nullifierVerifier library for checking nullifiers against a claimed value.
    // this can be used in the optional withdraw calls to verify that the nullifiers
    // match the withdrawn value
    IGroth16Verifier internal _withdrawVerifier;
    IGroth16Verifier internal _batchWithdrawVerifier;

    IERC20 internal _erc20;

    // Stored lock state, indexed by lockId.
    struct ZetoLockInfo {
        address owner;
        address spender;
        bytes32 spendCommitment;
        bytes32 cancelCommitment;
        // The locked content: the lockedOutputs from createLock, which become
        // the locked inputs for spendLock/cancelLock.
        uint256[] lockedInputs;
    }

    mapping(bytes32 => ZetoLockInfo) internal _locks;
    // Replay-protection map for caller-supplied txIds, keyed by (sender, txId).
    // Keying by txId alone would let any observer of the mempool front-run a
    // victim's lock-lifecycle call by submitting a tiny tx that reserves the
    // same global txId, causing the victim's tx to revert with
    // DuplicateTransaction. Per-sender keying preserves replay protection
    // for the legitimate caller while making the reservation collision-free
    // across senders. Combined with _computeLockId =
    // keccak256(address(this), msg.sender, txId), this also guarantees
    // lockIds derived from createLock are globally unique per-sender.
    mapping(address => mapping(bytes32 => bool)) internal _txIds;

    /// @dev Per-UTXO spender for any locked UTXO produced by this contract.
    ///
    ///      The lock-id-keyed `_locks[lockId].spender` is the source of
    ///      truth for which lock a spender is authorized over; this map is
    ///      a per-UTXO projection of that information so the public view
    ///      `locked(uint256)` can answer "(isLocked, currentSpender)" for
    ///      an arbitrary UTXO in O(1) without a UTXO -> lockId reverse
    ///      index. Kept in sync by {_setLockDelegates} (on lock creation,
    ///      delegation, and any new locked outputs produced by a spend)
    ///      and {_clearLockDelegates} (when locked inputs are consumed).
    ///
    ///      Authorization decisions MUST go through {onlySpender}/`_locks`,
    ///      never through this map.
    mapping(uint256 => address) internal _utxoDelegates;

    /// @dev Reserved storage to allow new state variables to be added in
    ///      future upgrades of this contract without shifting the storage
    ///      layout of inheriting contracts (e.g. ZetoFungibleNullifier and
    ///      its concrete implementations). Sized so that
    ///      `<state slots> + __gap.length == 50`, matching the OpenZeppelin
    ///      upgradeable convention. When a new state variable is added to
    ///      ZetoFungible, decrement the gap by the equivalent number of
    ///      slots so that descendants' layouts remain stable.
    uint256[49] private __gap;

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

    /// @dev Wipe the per-UTXO spender projection for each UTXO in `utxos`.
    ///      Called when a lock's inputs are consumed (spend or cancel) so
    ///      that the public {locked} view returns
    ///      `(false, address(0))` for them immediately, even if some
    ///      future code path were to resurrect the locked-state entry.
    function _clearLockDelegates(uint256[] memory utxos) internal {
        for (uint256 i = 0; i < utxos.length; ++i) {
            if (utxos[i] != 0) {
                delete _utxoDelegates[utxos[i]];
            }
        }
    }

    function __ZetoFungible_init(
        string calldata name_,
        string calldata symbol_,
        address initialOwner,
        IZetoInitializable.VerifiersInfo calldata verifiers,
        IZetoStorage storage_
    ) public onlyInitializing {
        __ZetoCommon_init(name_, symbol_, initialOwner, verifiers, storage_);
        __ReentrancyGuard_init();
        _depositVerifier = verifiers.depositVerifier;
        _withdrawVerifier = verifiers.withdrawVerifier;
        _batchWithdrawVerifier = verifiers.batchWithdrawVerifier;
    }

    /**
     * @dev Set the ERC20 token that this Zeto contract will interact with.
     *
     * @param erc20 The ERC20 token to be used.
     */
    function setERC20(IERC20 erc20) public onlyOwner {
        _erc20 = erc20;
    }

    /**
     * @dev the main function of the contract, which transfers values from one account (represented by Babyjubjub public keys)
     *      to one or more receiver accounts (also represented by Babyjubjub public keys). One of the two nullifiers may be zero
     *      if the transaction only needs one UTXO to be spent. Equally one of the two outputs may be zero if the transaction
     *      only needs to create one new UTXO.
     *
     * @param inputs Array of nullifiers that are secretly bound to UTXOs to be spent by the transaction.
     * @param outputs Array of new UTXOs to generate, for future transactions to spend.
     * @param proof A zero knowledge proof that the submitter is authorized to spend the inputs, and
     *      that the outputs are valid in terms of obeying mass conservation rules.
     *
     * Emits a {UTXOTransfer} event.
     */
    function transfer(
        uint256[] calldata inputs,
        uint256[] calldata outputs,
        bytes calldata proof,
        bytes calldata data
    ) public virtual {
        uint256[] memory lockedOutputs;
        validateTransactionProposal(
            inputs,
            outputs,
            lockedOutputs,
            proof,
            false
        );
        // Check and pad commitments
        (
            uint256[] memory paddedInputs,
            uint256[] memory paddedOutputs
        ) = checkAndPadCommitments(inputs, outputs);
        // construct the public inputs for the proof verification
        (
            uint256[] memory publicInputs,
            Commonlib.Proof memory proofStruct
        ) = constructPublicInputs(paddedInputs, paddedOutputs, proof, false);
        bool isBatch = (inputs.length > 2 || outputs.length > 2);
        verifyProof(proofStruct, publicInputs, isBatch, false);
        processInputsAndOutputs(paddedInputs, paddedOutputs, false);

        emitTransferEvent(inputs, outputs, proof, data);
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

    /// @inheritdoc IZetoLockableCapability
    function computeUnlockHash(
        uint256[] calldata lockedInputs,
        uint256[] calldata lockedOutputs,
        uint256[] calldata outputs,
        bytes calldata data
    ) external pure override returns (bytes32) {
        return _buildUnlockHash(lockedInputs, lockedOutputs, outputs, data);
    }

    /**
     * @dev Create a new lock by spending unlocked inputs and producing the
     *      locked content. See {ILockableCapability.createLock} for the
     *      generic semantics; the Zeto-specific payload is {ZetoCreateLockArgs}.
     *
     * Emits {LockCreated} (generic) and {ZetoLockCreated} (Zeto-specific).
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

        // Verify the ZK proof and consume inputs / produce locked outputs.
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
     * @dev Update the spend/cancel commitments on an active, owner-controlled
     *      lock. Mirrors the previous prepareUnlock flow but with full-update
     *      semantics: both commitments are replaced atomically.
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
        if (lock.spender != lock.owner) {
            revert LockImmutable(lockId);
        }
        if (msg.sender != lock.owner) {
            revert LockUnauthorized(lockId, lock.spender, msg.sender);
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
     * @dev Delegate spending authority for the lock. The per-UTXO spender
     *      projection used by the public {locked} view is also moved here so
     *      that subsequent observers see the new spender for every locked
     *      input belonging to this lock.
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
     *      If `spendCommitment` is non-zero, the supplied spendArgs MUST hash
     *      to it.
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

        // Snapshot the locked content from storage. The caller is intentionally
        // not allowed to substitute a different set of locked inputs.
        uint256[] memory lockedInputs = _locks[lockId].lockedInputs;
        bytes32 expectedHash = _locks[lockId].spendCommitment;
        _consumeLock(lockId, lockedInputs, expectedHash, args);

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
     * @dev Cancel the lock by executing the committed cancellation operation.
     *      If `cancelCommitment` is non-zero, the supplied cancelArgs MUST hash
     *      to it.
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
        _consumeLock(lockId, lockedInputs, expectedHash, args);

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

    /**
     * @dev Override of {ZetoCommon.locked} that fills in the per-UTXO
     *      spender from the {_utxoDelegates} projection. The storage
     *      layer only tells us "is this locked"; the spender lives at
     *      this layer because the lock model itself does.
     *
     *      Returns `(false, address(0))` for any UTXO that is not
     *      currently locked-unspent, including UTXOs whose lock has
     *      been spent or cancelled (since both `_lockedUtxos[X]` is
     *      flipped to `SPENT` and `_utxoDelegates[X]` is cleared in the
     *      consume path).
     */
    function locked(
        uint256 utxo
    ) public view override returns (bool, address) {
        if (!_storage.locked(utxo)) {
            return (false, address(0));
        }
        return (true, _utxoDelegates[utxo]);
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    function _doLockTransition(ZetoCreateLockArgs memory args) internal {
        validateTransactionProposal(
            args.inputs,
            args.outputs,
            args.lockedOutputs,
            args.proof,
            false
        );

        // Combine the locked outputs and the regular outputs because the
        // circuits do not differentiate them.
        uint256[] memory allOutputs = new uint256[](
            args.lockedOutputs.length + args.outputs.length
        );
        for (uint256 i = 0; i < args.lockedOutputs.length; i++) {
            allOutputs[i] = args.lockedOutputs[i];
        }
        for (uint256 i = 0; i < args.outputs.length; i++) {
            allOutputs[args.lockedOutputs.length + i] = args.outputs[i];
        }

        (
            uint256[] memory paddedInputs,
            uint256[] memory paddedOutputs
        ) = checkAndPadCommitments(args.inputs, allOutputs);

        (
            uint256[] memory publicInputs,
            Commonlib.Proof memory proofStruct
        ) = constructPublicInputs(
                paddedInputs,
                paddedOutputs,
                args.proof,
                false
            );

        bool isBatch = (paddedInputs.length > 2 ||
            args.outputs.length > 2 ||
            args.lockedOutputs.length > 2);
        verifyProof(proofStruct, publicInputs, isBatch, false);

        processInputsAndOutputs(paddedInputs, args.outputs, false);
        processLockedOutputs(args.lockedOutputs);
        // The freshly-locked outputs all start under the lock creator as
        // both owner and spender; record that on the per-UTXO projection
        // so {locked} can report it without a reverse lookup.
        _setLockDelegates(args.lockedOutputs, msg.sender);
    }

    /**
     * @dev Consume an active lock.
     *
     *      `lockedInputs` MUST be the lock's storage-pinned content (read by
     *      the caller from `_locks[lockId].lockedInputs`). The spender does
     *      not get to choose which UTXOs are consumed: that decision was made
     *      at {createLock} time. This is what makes "spending lock A consumes
     *      lock A's UTXOs" a hard contract invariant.
     */
    function _consumeLock(
        bytes32 lockId,
        uint256[] memory lockedInputs,
        bytes32 expectedHash,
        ZetoSpendLockArgs memory args
    ) internal {
        _useTxId(args.txId);

        if (expectedHash != 0) {
            bytes32 actualHash = _buildUnlockHash(
                lockedInputs,
                args.lockedOutputs,
                args.outputs,
                args.data
            );
            if (actualHash != expectedHash) {
                revert InvalidUnlockHash(expectedHash, actualHash);
            }
        }

        // Tear down all lock-spender state BEFORE performing the state
        // transition, so any reentrant lookup observes both `_locks[lockId]`
        // and the per-UTXO `_utxoDelegates` projection as cleared.
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

    /**
     * @dev Deposit ERC20 tokens into the Zeto contract.
     *
     * @param amount The amount of ERC20 tokens to be deposited.
     * @param outputs The UTXOs to be minted.
     * @param proof The proof of the deposit.
     * @param data Additional data to be passed to the deposit function.
     *
     * Emits a {UTXOMint} event.
     */
    function deposit(
        uint256 amount,
        uint256[] calldata outputs,
        bytes calldata proof,
        bytes calldata data
    ) public nonReentrant {
        // ---- Checks ----
        validateOutputs(outputs);

        // verifies that the output UTXOs match the claimed value
        // to be deposited
        (
            uint256[] memory publicInputs,
            Commonlib.Proof memory proofStruct
        ) = constructPublicInputsForDeposit(amount, outputs, proof);
        require(
            _depositVerifier.verify(
                proofStruct.pA,
                proofStruct.pB,
                proofStruct.pC,
                publicInputs
            ),
            "Invalid proof"
        );

        // ---- Effects ----
        // Mint the UTXOs (commits the new outputs to storage and emits
        // {UTXOMint}) before the external ERC20 call. This ensures that any
        // reentrant call into this contract triggered by the ERC20 transfer
        // observes the new outputs as already-committed and cannot replay them.
        _mint(outputs, data);

        // ---- Interactions ----
        require(
            _erc20.transferFrom(msg.sender, address(this), amount),
            "Failed to transfer ERC20 tokens"
        );
    }

    /**
     * @dev Withdraw ERC20 tokens from the Zeto contract.
     *
     * @param amount The amount of ERC20 tokens to be withdrawn.
     * @param inputs The UTXOs to be spent.
     * @param output The UTXO to be minted.
     * @param proof The proof of the withdrawal.
     * @param data Additional data to be passed to the withdrawal function.
     *
     * Emits a {UTXOWithdraw} event.
     */
    function withdraw(
        uint256 amount,
        uint256[] calldata inputs,
        uint256 output,
        bytes calldata proof,
        bytes calldata data
    ) public nonReentrant {
        uint256[] memory outputs = new uint256[](1);
        outputs[0] = output;
        uint256[] memory lockedOutputs;

        // ---- Checks ----
        validateTransactionProposal(
            inputs,
            outputs,
            lockedOutputs,
            proof,
            false
        );
        // Check and pad inputs and outputs based on the max size
        (
            uint256[] memory paddedInputs,
            uint256[] memory paddedOutputs
        ) = checkAndPadCommitments(inputs, outputs);
        (
            uint256[] memory publicInputs,
            Commonlib.Proof memory proofStruct
        ) = constructPublicInputsForWithdraw(
                amount,
                paddedInputs,
                output,
                proof
            );
        IGroth16Verifier verifier = (inputs.length > 2)
            ? _batchWithdrawVerifier
            : _withdrawVerifier;
        require(
            verifier.verify(
                proofStruct.pA,
                proofStruct.pB,
                proofStruct.pC,
                publicInputs
            ),
            "Invalid proof"
        );

        // ---- Effects ----
        // Mark the input nullifiers as spent and commit the change-output
        // before performing the external ERC20 transfer. Following
        // checks-effects-interactions ensures a callback-style ERC20 cannot
        // re-enter and double-spend the same nullifiers.
        processInputsAndOutputs(paddedInputs, paddedOutputs, false);

        // ---- Interactions ----
        require(
            _erc20.transfer(msg.sender, amount),
            "Failed to transfer ERC20 tokens"
        );

        // Emitted after the transfer so that the on-chain event order remains
        // ERC20.Transfer → UTXOWithdraw, matching listeners and tests built
        // before the CEI reorder. Event emission is a pure log and does not
        // affect security; the nullifier state was already committed above.
        emit UTXOWithdraw(amount, inputs, output, msg.sender, data);
    }

    function emitTransferEvent(
        uint256[] memory inputs,
        uint256[] memory outputs,
        bytes memory proof,
        bytes memory data
    ) internal virtual {
        emit UTXOTransfer(inputs, outputs, msg.sender, data);
    }

    function _buildUnlockHash(
        uint256[] memory lockedInputs,
        uint256[] memory lockedOutputs,
        uint256[] memory outputs,
        bytes memory data
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    keccak256(abi.encodePacked(lockedInputs)),
                    keccak256(abi.encodePacked(lockedOutputs)),
                    keccak256(abi.encodePacked(outputs)),
                    keccak256(data)
                )
            );
    }

    function _transferLocked(
        bytes32 lockId,
        uint256[] memory lockedInputs,
        uint256[] memory lockedOutputs,
        uint256[] memory outputs,
        bytes memory proof,
        bytes memory data
    ) internal virtual {
        validateTransactionProposal(
            lockedInputs,
            outputs,
            lockedOutputs,
            proof,
            true
        );
        // combine the locked outputs and the outputs, because the circuits
        // do not care about the difference between locked and unlocked outputs
        uint256[] memory allOutputs = new uint256[](
            lockedOutputs.length + outputs.length
        );
        for (uint256 i = 0; i < lockedOutputs.length; i++) {
            allOutputs[i] = lockedOutputs[i];
        }
        for (uint256 i = 0; i < outputs.length; i++) {
            allOutputs[lockedOutputs.length + i] = outputs[i];
        }
        // Check and pad inputs and outputs based on the max size
        (
            uint256[] memory paddedInputs,
            uint256[] memory paddedOutputs
        ) = checkAndPadCommitments(lockedInputs, allOutputs);
        // construct the public inputs for the proof verification
        (
            uint256[] memory publicInputs,
            Commonlib.Proof memory proofStruct
        ) = constructPublicInputs(paddedInputs, paddedOutputs, proof, true);
        bool isBatch = (lockedInputs.length > 2 || allOutputs.length > 2);
        verifyProof(proofStruct, publicInputs, isBatch, true);
        processInputsAndOutputs(paddedInputs, paddedOutputs, true);
        processLockedOutputs(lockedOutputs);
        // Any newly-locked outputs produced by this spend default to the
        // current spender as their delegate. (When `lockedOutputs` is empty
        // -- the common case -- this is a no-op.)
        _setLockDelegates(lockedOutputs, msg.sender);
    }

    // this is a utility function that constructs the public inputs for a proof of a deposit() call.
    // specific implementations of this function may be overridden by each token implementation
    function constructPublicInputsForDeposit(
        uint256 amount,
        uint256[] memory outputs,
        bytes memory proof
    ) public virtual returns (uint256[] memory, Commonlib.Proof memory) {
        Commonlib.Proof memory proofStruct = abi.decode(
            proof,
            (Commonlib.Proof)
        );
        // construct the public inputs
        uint256[] memory extra = extraInputsForDeposit();
        uint256[] memory publicInputs = new uint256[](3 + extra.length);
        publicInputs[0] = amount;
        publicInputs[1] = outputs[0];
        publicInputs[2] = outputs[1];
        for (uint256 i = 0; i < extra.length; i++) {
            publicInputs[3 + i] = extra[i];
        }

        return (publicInputs, proofStruct);
    }

    function extraInputsForDeposit()
        internal
        view
        virtual
        returns (uint256[] memory)
    {
        return new uint256[](0);
    }

    // this is a utility function that constructs the public inputs for a proof of a withdraw() call.
    // specific implementations of this function may be overridden by each token implementation
    function constructPublicInputsForWithdraw(
        uint256 amount,
        uint256[] memory inputs,
        uint256 output,
        bytes memory proof
    ) internal virtual returns (uint256[] memory, Commonlib.Proof memory) {
        Commonlib.Proof memory proofStruct = abi.decode(
            proof,
            (Commonlib.Proof)
        );
        uint256 size = (inputs.length + 1 + 1); // inputs, output, and amount

        uint256[] memory publicInputs = new uint256[](size);
        uint256 piIndex = 0;

        // copy output amount
        publicInputs[piIndex++] = amount;

        // copy input commitments
        for (uint256 i = 0; i < inputs.length; i++) {
            publicInputs[piIndex++] = inputs[i];
        }

        // copy output commitment
        publicInputs[piIndex++] = output;

        return (publicInputs, proofStruct);
    }
}
