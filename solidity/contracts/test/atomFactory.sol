// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import {Atom} from "./Atom.sol";

// https://www.alchemy.com/docs/create2-an-alternative-to-deriving-contract-addresses
contract Create2Factory {
    event Deploy(address addr);

    function deploy(
        bytes memory bytecode,
        uint _salt
    ) internal returns (address) {
        address addr;
        assembly {
            addr := create2(0, add(bytecode, 0x20), mload(bytecode), _salt)
            if iszero(extcodesize(addr)) {
                revert(0, 0)
            }
        }
        return addr;
    }
}

contract AtomFactory is Create2Factory {
    function deployAtom(
        bytes memory bytecode,
        uint _salt,
        Atom.Operation[] calldata operations
    ) public {
        address instance = super.deploy(bytecode, _salt);
        Atom(instance).initialize(operations);
        emit Deploy(instance);
    }
}
