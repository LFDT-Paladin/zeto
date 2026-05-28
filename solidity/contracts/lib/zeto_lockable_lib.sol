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

import {ILockableCapability} from "./interfaces/ILockableCapability.sol";
import {IZetoLockableCapability} from "./interfaces/IZetoLockableCapability.sol";
import {IZetoLockHooks} from "./interfaces/IZetoLockHooks.sol";
import {ZetoCommonStorage} from "./zeto_common.sol";
import {ZetoLockableStorage} from "./zeto_lockable_storage.sol";

/// @title ZetoLockableLib
/// @author Kaleido, Inc.
/// @dev External library holding the shared {IZetoLockableCapability} lock
///      lifecycle. Deploy once per chain and link into every Zeto token
///      implementation; logic runs in the token's storage context via
///      `DELEGATECALL`. Circuit-specific work is delegated back to the
///      embedding token through {IZetoLockHooks}.
library ZetoLockableLib {
    /// @dev Domain-separation tag for spend-intent commitments.
    bytes32 private constant _SPEND_HASH_DOMAIN =
        keccak256("Zeto.spendCommitment.v1");

    /// @dev Domain-separation tag for cancel-intent commitments.
    bytes32 private constant _CANCEL_HASH_DOMAIN =
        keccak256("Zeto.cancelCommitment.v1");

    function computeLockId(
        bytes calldata createArgs
    ) public view returns (bytes32) {
        IZetoLockableCapability.ZetoCreateLockArgs memory args = abi.decode(
            createArgs,
            (IZetoLockableCapability.ZetoCreateLockArgs)
        );
        return _computeLockId(args.txId);
    }

    function computeSpendHash(
        uint256[] calldata lockedInputs,
        uint256[] calldata lockedOutputs,
        uint256[] calldata outputs,
        bytes calldata data
    ) public pure returns (bytes32) {
        return
            _buildUnlockHash(
                lockedInputs,
                lockedOutputs,
                outputs,
                data,
                _SPEND_HASH_DOMAIN
            );
    }

    function computeCancelHash(
        uint256[] calldata lockedInputs,
        uint256[] calldata lockedOutputs,
        uint256[] calldata outputs,
        bytes calldata data
    ) public pure returns (bytes32) {
        return
            _buildUnlockHash(
                lockedInputs,
                lockedOutputs,
                outputs,
                data,
                _CANCEL_HASH_DOMAIN
            );
    }

    function createLock(
        bytes calldata createArgs,
        bytes32 spendCommitment,
        bytes32 cancelCommitment,
        bytes calldata data
    ) public returns (bytes32) {
        IZetoLockableCapability.ZetoCreateLockArgs memory args = abi.decode(
            createArgs,
            (IZetoLockableCapability.ZetoCreateLockArgs)
        );

        bytes32 lockId = _computeLockId(args.txId);
        if (ZetoLockableStorage.layout().locks[lockId].owner != address(0)) {
            revert IZetoLockableCapability.DuplicateLock(lockId);
        }
        _useTxId(args.txId);

        IZetoLockHooks(address(this)).zetoLockDoLockTransition(args);

        // Delegate projection must be set here (not in the hook): the hook
        // runs as an external self-call where msg.sender is address(this).
        setLockDelegates(args.lockedOutputs, msg.sender);

        ZetoLockableStorage.ZetoLockInfo storage lock = ZetoLockableStorage
            .layout()
            .locks[lockId];
        lock.owner = msg.sender;
        lock.spender = msg.sender;
        lock.spendCommitment = spendCommitment;
        lock.cancelCommitment = cancelCommitment;
        lock.lockedInputs = args.lockedOutputs;

        emit ILockableCapability.LockCreated(
            lockId,
            msg.sender,
            msg.sender,
            spendCommitment,
            cancelCommitment,
            data
        );
        emit IZetoLockableCapability.ZetoLockCreated(
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

    function updateLock(
        bytes32 lockId,
        bytes calldata updateArgs,
        bytes32 spendCommitment,
        bytes32 cancelCommitment,
        bytes calldata data
    ) public {
        _requireLockActive(lockId);
        _requireLockOwner(lockId);

        ZetoLockableStorage.ZetoLockInfo storage lock = ZetoLockableStorage
            .layout()
            .locks[lockId];
        if (lock.spender != lock.owner) {
            revert ILockableCapability.LockImmutable(lockId);
        }

        IZetoLockableCapability.ZetoUpdateLockArgs memory args = abi.decode(
            updateArgs,
            (IZetoLockableCapability.ZetoUpdateLockArgs)
        );
        _useTxId(args.txId);

        lock.spendCommitment = spendCommitment;
        lock.cancelCommitment = cancelCommitment;

        emit ILockableCapability.LockUpdated(
            lockId,
            msg.sender,
            spendCommitment,
            cancelCommitment,
            data
        );
        emit IZetoLockableCapability.ZetoLockUpdated(
            args.txId,
            lockId,
            msg.sender,
            data
        );
    }

    function delegateLock(
        bytes32 lockId,
        bytes calldata delegateArgs,
        address newSpender,
        bytes calldata data
    ) public {
        _requireLockActive(lockId);
        _requireLockSpender(lockId);

        IZetoLockableCapability.ZetoDelegateLockArgs memory args = abi.decode(
            delegateArgs,
            (IZetoLockableCapability.ZetoDelegateLockArgs)
        );
        _useTxId(args.txId);

        ZetoLockableStorage.ZetoLockInfo storage lock = ZetoLockableStorage
            .layout()
            .locks[lockId];
        address previousSpender = lock.spender;
        lock.spender = newSpender;

        setLockDelegates(lock.lockedInputs, newSpender);

        emit ILockableCapability.LockDelegated(
            lockId,
            previousSpender,
            newSpender,
            data
        );
        emit IZetoLockableCapability.ZetoLockDelegated(
            args.txId,
            lockId,
            previousSpender,
            newSpender,
            data
        );
    }

    function spendLock(
        bytes32 lockId,
        bytes calldata spendArgs,
        bytes calldata data
    ) public {
        _requireLockActive(lockId);
        _requireLockSpender(lockId);

        IZetoLockableCapability.ZetoSpendLockArgs memory args = abi.decode(
            spendArgs,
            (IZetoLockableCapability.ZetoSpendLockArgs)
        );

        uint256[] memory lockedInputs = ZetoLockableStorage
            .layout()
            .locks[lockId]
            .lockedInputs;
        bytes32 expectedHash = ZetoLockableStorage
            .layout()
            .locks[lockId]
            .spendCommitment;
        _consumeLock(
            lockId,
            lockedInputs,
            expectedHash,
            _SPEND_HASH_DOMAIN,
            args
        );

        emit ILockableCapability.LockSpent(lockId, msg.sender, data);
        emit IZetoLockableCapability.ZetoLockSpent(
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

    function cancelLock(
        bytes32 lockId,
        bytes calldata cancelArgs,
        bytes calldata data
    ) public {
        _requireLockActive(lockId);
        _requireLockSpender(lockId);

        IZetoLockableCapability.ZetoSpendLockArgs memory args = abi.decode(
            cancelArgs,
            (IZetoLockableCapability.ZetoSpendLockArgs)
        );

        uint256[] memory lockedInputs = ZetoLockableStorage
            .layout()
            .locks[lockId]
            .lockedInputs;
        bytes32 expectedHash = ZetoLockableStorage
            .layout()
            .locks[lockId]
            .cancelCommitment;
        _consumeLock(
            lockId,
            lockedInputs,
            expectedHash,
            _CANCEL_HASH_DOMAIN,
            args
        );

        emit ILockableCapability.LockCancelled(lockId, msg.sender, data);
        emit IZetoLockableCapability.ZetoLockCancelled(
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

    function getLock(
        bytes32 lockId
    ) public view returns (ILockableCapability.LockInfo memory) {
        _requireLockActive(lockId);
        ZetoLockableStorage.ZetoLockInfo storage lock = ZetoLockableStorage
            .layout()
            .locks[lockId];
        return
            ILockableCapability.LockInfo({
                owner: lock.owner,
                spender: lock.spender,
                spendCommitment: lock.spendCommitment,
                cancelCommitment: lock.cancelCommitment
            });
    }

    function isLockActive(bytes32 lockId) public view returns (bool) {
        return ZetoLockableStorage.layout().locks[lockId].owner != address(0);
    }

    function getLockContent(
        bytes32 lockId
    ) public view returns (bytes memory content) {
        _requireLockActive(lockId);
        return
            abi.encode(ZetoLockableStorage.layout().locks[lockId].lockedInputs);
    }

    function getLockedInputs(
        bytes32 lockId
    ) public view returns (uint256[] memory lockedInputs) {
        _requireLockActive(lockId);
        return ZetoLockableStorage.layout().locks[lockId].lockedInputs;
    }

    function locked(uint256 utxo) public view returns (bool, address) {
        if (!ZetoCommonStorage.layout().utxoStorage.locked(utxo)) {
            return (false, address(0));
        }
        return (true, ZetoLockableStorage.layout().utxoDelegates[utxo]);
    }

    function setLockDelegates(
        uint256[] memory utxos,
        address spender
    ) public {
        for (uint256 i = 0; i < utxos.length; ++i) {
            if (utxos[i] != 0) {
                ZetoLockableStorage.layout().utxoDelegates[utxos[i]] = spender;
            }
        }
    }

    function _computeLockId(bytes32 txId) private view returns (bytes32) {
        return keccak256(abi.encode(address(this), msg.sender, txId));
    }

    function _useTxId(bytes32 txId) private {
        if (ZetoLockableStorage.layout().txIds[msg.sender][txId]) {
            revert IZetoLockableCapability.DuplicateTransaction(txId);
        }
        ZetoLockableStorage.layout().txIds[msg.sender][txId] = true;
    }

    function _requireLockActive(bytes32 lockId) private view {
        if (ZetoLockableStorage.layout().locks[lockId].owner == address(0)) {
            revert ILockableCapability.LockNotActive(lockId);
        }
    }

    function _requireLockOwner(bytes32 lockId) private view {
        address owner = ZetoLockableStorage.layout().locks[lockId].owner;
        if (owner != msg.sender) {
            revert ILockableCapability.LockUnauthorized(
                lockId,
                owner,
                msg.sender
            );
        }
    }

    function _requireLockSpender(bytes32 lockId) private view {
        address spender = ZetoLockableStorage.layout().locks[lockId].spender;
        if (spender != msg.sender) {
            revert ILockableCapability.LockUnauthorized(
                lockId,
                spender,
                msg.sender
            );
        }
    }

    function _consumeLock(
        bytes32 lockId,
        uint256[] memory lockedInputs,
        bytes32 expectedHash,
        bytes32 hashDomain,
        IZetoLockableCapability.ZetoSpendLockArgs memory args
    ) private {
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
                revert IZetoLockableCapability.InvalidUnlockHash(
                    expectedHash,
                    actualHash
                );
            }
        }

        _clearLockDelegates(lockedInputs);
        delete ZetoLockableStorage.layout().locks[lockId];

        IZetoLockHooks(address(this)).zetoLockTransferLocked(
            lockId,
            lockedInputs,
            args.lockedOutputs,
            args.outputs,
            args.proof,
            args.data
        );

        // Same msg.sender rationale as {createLock}: hook is external self-call.
        if (args.lockedOutputs.length > 0) {
            setLockDelegates(args.lockedOutputs, msg.sender);
        }
    }

    function _clearLockDelegates(uint256[] memory utxos) private {
        for (uint256 i = 0; i < utxos.length; ++i) {
            if (utxos[i] != 0) {
                delete ZetoLockableStorage.layout().utxoDelegates[utxos[i]];
            }
        }
    }

    function _buildUnlockHash(
        uint256[] memory lockedInputs,
        uint256[] memory lockedOutputs,
        uint256[] memory outputs,
        bytes memory data,
        bytes32 domain
    ) private pure returns (bytes32) {
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
