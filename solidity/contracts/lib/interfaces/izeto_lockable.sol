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

interface IZetoLockable {
    error UTXOAlreadyLocked(uint256 utxo);
    error UTXONotLocked(uint256 utxo);
    error NotLockDelegate(
        uint256 utxo,
        address currentDelegate,
        address sender
    );
    event UTXOLocked(
        uint256[] inputs,
        uint256[] lockedOutputs,
        uint256[] outputs,
        address indexed submitter,
        address indexed delegate,
        bytes data
    );
    event LockDelegateChanged(
        uint256[] lockedOutputs,
        address indexed oldDelegate,
        address indexed newDelegate,
        bytes data
    );
}
