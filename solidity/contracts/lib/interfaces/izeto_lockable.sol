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

import {ILockable} from "./ILockable.sol";

interface IZetoLockable is ILockable {
    error AlreadyLocked(uint256 utxo);
    error UnlockAlreadyPrepared(bytes32 lockId);
    error UnlockNotPrepared(bytes32 lockId);
    error InvalidUnlockHash(bytes32 expected, bytes32 actual);
    error NotLocked(uint256 utxo);
    error NotLockDelegate(
        uint256 utxo,
        address currentDelegate,
        address sender
    );
    event LockCreate(
        bytes32 lockId,
        address indexed operator,
        LockData lockData,
        bytes data
    );
    event UnlockPrepare(
        bytes32 lockId,
        address indexed operator,
        UnlockOperation settle,
        bytes data
    );
    event Unlock(
        bytes32 lockId,
        address indexed operator,
        uint256[] inputs,
        address indexed delegate,
        UnlockOperationData settle
    );
    event LockRollback(
        bytes32 lockId,
        address indexed operator,
        uint256[] inputs,
        address indexed delegate,
        UnlockOperationData rollback
    );
    event LockDelegate(
        bytes32 lockId,
        address indexed operator,
        address indexed oldDelegate,
        address indexed newDelegate,
        bytes data
    );

    // expected to be used in a map from lockId to LockData
    struct LockData {
        // Array of states that are secured by this lock
        uint256[] inputs;
        // the account that is authorized to carry out the operations on the lock
        address delegate;
        // the operation to execute when the lock is executed
        UnlockOperation settle;
    }

    // Used to prepare the unlock operation for the lock, and
    // represents the committed unlock operation
    struct UnlockOperation {
        // this is the keccak256 hash of the inputs, outputs and "data" fields
        bytes32 unlockHash;
    }

    // used in function parameters to avoid stack too deep errors
    struct LockParameters {
        // Array of states that are secured by this lock
        uint256[] inputs;
        // Array of zero or more new states to generate, for future transactions to spend
        uint256[] outputs;
        // Array of zero or more locked states to generate, which will be tied to the lockId
        uint256[] lockedOutputs;
    }

    function lock(
        bytes32 lockId,
        LockParameters calldata parameters,
        bytes calldata proof,
        bytes calldata data
    ) external;

    function prepareUnlock(
        bytes32 lockId,
        UnlockOperation calldata settle,
        bytes calldata data
    ) external;

    function delegateLock(
        bytes32 lockId,
        address delegate,
        bytes calldata data
    ) external;
}
