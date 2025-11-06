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

import {Commonlib} from "../common/common.sol";
import {ILockable} from "./ILockable.sol";

interface IZetoLockable is ILockable {
    error AlreadyLocked(uint256 utxo);
    error NotLocked(uint256 utxo);
    error NotLockDelegate(
        uint256 utxo,
        address currentDelegate,
        address sender
    );
    event LockPrepare(
        address indexed operator,
        LockParameters states,
        address delegate,
        bytes data
    );
    event LockCommit(
        bytes32 lockId,
        address indexed operator,
        LockData lockData,
        bytes data
    );
    event LockDelegation(
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
        LockOperationData settle;
        // the operation to execute when the lock is retracted
        LockOperationData refund;
    }

    struct LockOperationData {
        LockOutputStates outputStates;
        bytes proof;
        bytes data;
    }

    struct LockOutputStates {
        // Array of zero or more new states to generate, for future transactions to spend
        uint256[] outputs;
        // Array of zero or more locked states to generate, which will be tied to the lockId
        uint256[] lockedOutputs;
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

    function prepareLock(
        LockParameters calldata states,
        address delegate,
        bytes calldata proof,
        bytes calldata data
    ) external;

    function commitLock(
        bytes32 lockId,
        uint256[] calldata inputs,
        address delegate,
        LockOperationData calldata execute,
        LockOperationData calldata rollback,
        bytes calldata data
    ) external;

    function delegateLock(
        bytes32 lockId,
        address delegate,
        bytes calldata data
    ) external;
}
