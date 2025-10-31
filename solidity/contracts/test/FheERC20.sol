// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {FHE, euint64, externalEuint64} from "@fhevm/solidity/lib/FHE.sol";
import {SepoliaConfig} from "@fhevm/solidity/config/ZamaConfig.sol";
import {ERC7984} from "@openzeppelin/confidential-contracts/token/ERC7984/ERC7984.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

// only used in hardhat tests
// import {Atom} from "paladin/contracts/shared/Atom.sol";

contract FheERC20 is ERC7984, Ownable, SepoliaConfig {
    constructor()
        ERC7984("Test ERC7984", "tERC7984", "https://test.com")
        Ownable(msg.sender)
    {}

    function mint(
        address to,
        externalEuint64 amount,
        bytes calldata proof
    ) public onlyOwner {
        euint64 encryptedAmount = FHE.fromExternal(amount, proof);
        _mint(to, encryptedAmount);
    }

    function burn(
        address from,
        externalEuint64 amount,
        bytes calldata proof
    ) public onlyOwner {
        euint64 encryptedAmount = FHE.fromExternal(amount, proof);
        _burn(from, encryptedAmount);
    }
}
