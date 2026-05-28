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
import {IZetoLockHooks} from "./interfaces/IZetoLockHooks.sol";
import {ILockableCapability} from "./interfaces/ILockableCapability.sol";
import {ZetoCommon} from "./zeto_common.sol";
import {ZetoLockableLib} from "./zeto_lockable_lib.sol";

/// @title ZetoLockable
/// @author Kaleido, Inc.
/// @dev Thin embedding layer for {IZetoLockableCapability}. Shared lock
///      lifecycle logic lives in the linked external {ZetoLockableLib};
///      this contract forwards interface entry points to the library and
///      exposes {IZetoLockHooks} callbacks for circuit-specific work in
///      descendants ({ZetoFungible}, {ZetoNonFungible}).
abstract contract ZetoLockable is
    ZetoCommon,
    IZetoLockableCapability,
    IZetoLockHooks
{
    modifier onlySelf() {
        if (msg.sender != address(this)) {
            revert NotSelf(msg.sender);
        }
        _;
    }

    /// @inheritdoc IZetoLockableCapability
    function computeLockId(
        bytes calldata createArgs
    ) external view override returns (bytes32) {
        return ZetoLockableLib.computeLockId(createArgs);
    }

    /// @inheritdoc IZetoLockableCapability
    function computeSpendHash(
        uint256[] calldata lockedInputs,
        uint256[] calldata lockedOutputs,
        uint256[] calldata outputs,
        bytes calldata data
    ) external pure override returns (bytes32) {
        return
            ZetoLockableLib.computeSpendHash(
                lockedInputs,
                lockedOutputs,
                outputs,
                data
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
            ZetoLockableLib.computeCancelHash(
                lockedInputs,
                lockedOutputs,
                outputs,
                data
            );
    }

    /// @inheritdoc ILockableCapability
    function createLock(
        bytes calldata createArgs,
        bytes32 spendCommitment,
        bytes32 cancelCommitment,
        bytes calldata data
    ) external override returns (bytes32) {
        return
            ZetoLockableLib.createLock(
                createArgs,
                spendCommitment,
                cancelCommitment,
                data
            );
    }

    /// @inheritdoc ILockableCapability
    function updateLock(
        bytes32 lockId,
        bytes calldata updateArgs,
        bytes32 spendCommitment,
        bytes32 cancelCommitment,
        bytes calldata data
    ) external override {
        ZetoLockableLib.updateLock(
            lockId,
            updateArgs,
            spendCommitment,
            cancelCommitment,
            data
        );
    }

    /// @inheritdoc ILockableCapability
    function delegateLock(
        bytes32 lockId,
        bytes calldata delegateArgs,
        address newSpender,
        bytes calldata data
    ) external override {
        ZetoLockableLib.delegateLock(
            lockId,
            delegateArgs,
            newSpender,
            data
        );
    }

    /// @inheritdoc ILockableCapability
    function spendLock(
        bytes32 lockId,
        bytes calldata spendArgs,
        bytes calldata data
    ) external override {
        ZetoLockableLib.spendLock(lockId, spendArgs, data);
    }

    /// @inheritdoc ILockableCapability
    function cancelLock(
        bytes32 lockId,
        bytes calldata cancelArgs,
        bytes calldata data
    ) external override {
        ZetoLockableLib.cancelLock(lockId, cancelArgs, data);
    }

    /// @inheritdoc ILockableCapability
    function getLock(
        bytes32 lockId
    ) external view override returns (LockInfo memory) {
        return ZetoLockableLib.getLock(lockId);
    }

    /// @inheritdoc ILockableCapability
    function isLockActive(
        bytes32 lockId
    ) external view override returns (bool) {
        return ZetoLockableLib.isLockActive(lockId);
    }

    /// @inheritdoc ILockableCapability
    function getLockContent(
        bytes32 lockId
    ) external view override returns (bytes memory content) {
        return ZetoLockableLib.getLockContent(lockId);
    }

    /// @inheritdoc IZetoLockableCapability
    function getLockedInputs(
        bytes32 lockId
    ) external view override returns (uint256[] memory lockedInputs) {
        return ZetoLockableLib.getLockedInputs(lockId);
    }

    /// @inheritdoc ZetoCommon
    function locked(uint256 utxo) public view override returns (bool, address) {
        return ZetoLockableLib.locked(utxo);
    }

    /// @inheritdoc IZetoLockHooks
    function zetoLockDoLockTransition(
        ZetoCreateLockArgs calldata args
    ) external override onlySelf {
        _doLockTransition(args);
    }

    /// @inheritdoc IZetoLockHooks
    function zetoLockTransferLocked(
        bytes32 lockId,
        uint256[] calldata lockedInputs,
        uint256[] calldata lockedOutputs,
        uint256[] calldata outputs,
        bytes calldata proof,
        bytes calldata data
    ) external override onlySelf {
        _transferLocked(
            lockId,
            lockedInputs,
            lockedOutputs,
            outputs,
            proof,
            data
        );
    }

    function _doLockTransition(
        ZetoCreateLockArgs calldata args
    ) internal virtual;

    function _transferLocked(
        bytes32 lockId,
        uint256[] calldata lockedInputs,
        uint256[] calldata lockedOutputs,
        uint256[] calldata outputs,
        bytes calldata proof,
        bytes calldata data
    ) internal virtual;
}
