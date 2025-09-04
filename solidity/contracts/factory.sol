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

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IZetoInitializable} from "./lib/interfaces/izeto_initializable.sol";

contract ZetoTokenFactory is Ownable {
    // all the addresses needed by the factory to
    // clone a Zeto token and initialize it. The
    // "implementation" is used to clone the token,
    // the rest of the addresses are used to initialize
    struct ImplementationInfo {
        address implementation;
        IZetoInitializable.VerifiersInfo verifiers;
    }

    event ZetoTokenDeployed(address indexed zetoToken);

    mapping(string => ImplementationInfo) internal implementations;

    constructor() Ownable(msg.sender) {}

    function registerImplementation(
        string calldata name,
        ImplementationInfo memory implementation
    ) public onlyOwner {
        require(
            implementation.implementation != address(0),
            "Factory: implementation address is required"
        );
        require(
            address(implementation.verifiers.verifier) != address(0),
            "Factory: verifier address is required"
        );
        // the depositVerifier and withdrawVerifier are optional
        // for the non-fungible token implementations
        implementations[name] = implementation;
    }

    function deployZetoFungibleToken(
        string calldata name,
        string calldata symbol,
        string calldata tokenImplementation,
        address initialOwner
    ) public returns (address) {
        ImplementationInfo memory args = implementations[tokenImplementation];
        require(
            args.implementation != address(0),
            "Factory: failed to find implementation"
        );
        // check that the registered implementation is for a fungible token
        // and has the required verifier addresses
        require(
            address(args.verifiers.depositVerifier) != address(0),
            "Factory: depositVerifier address is required"
        );
        require(
            address(args.verifiers.withdrawVerifier) != address(0),
            "Factory: withdrawVerifier address is required"
        );
        require(
            address(args.verifiers.batchVerifier) != address(0),
            "Factory: batchVerifier address is required"
        );
        require(
            address(args.verifiers.batchWithdrawVerifier) != address(0),
            "Factory: batchWithdrawVerifier address is required"
        );
        address instance = address(
            new ERC1967Proxy(
                args.implementation,
                abi.encodeCall(
                    IZetoInitializable.initialize,
                    (name, symbol, initialOwner, args.verifiers)
                )
            )
        );
        emit ZetoTokenDeployed(instance);
        return instance;
    }

    function deployZetoNonFungibleToken(
        string calldata name,
        string calldata symbol,
        string calldata tokenImplementation,
        address initialOwner
    ) public returns (address) {
        ImplementationInfo memory args = implementations[tokenImplementation];
        require(
            args.implementation != address(0),
            "Factory: failed to find implementation"
        );
        address instance = address(
            new ERC1967Proxy(
                args.implementation,
                abi.encodeCall(
                    IZetoInitializable.initialize,
                    (name, symbol, initialOwner, args.verifiers)
                )
            )
        );
        emit ZetoTokenDeployed(instance);
        return instance;
    }
}
