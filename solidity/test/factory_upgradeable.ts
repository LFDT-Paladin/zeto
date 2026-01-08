// Copyright © 2026 Kaleido, Inc.
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

import { ethers, network, upgrades } from "hardhat";
import { Signer } from "ethers";
import { expect } from "chai";

describe("(factory upgradeable) Zeto based fungible token with anonymity without encryption or nullifier", function () {
  let deployer: Signer;
  let nonOwner: Signer;

  before(async function () {
    if (network.name !== "hardhat") {
      // accommodate for longer block times on public networks
      this.timeout(120000);
    }
    [deployer, nonOwner] = await ethers.getSigners();
  });

  async function deployFactory() {
    const Factory = await ethers.getContractFactory(
      "ZetoTokenFactoryUpgradeable",
    );
    const proxy = await upgrades.deployProxy(Factory, [], {
      kind: "uups",
      initializer: "initialize",
    });
    await proxy.waitForDeployment();
    return await ethers.getContractAt(
      "ZetoTokenFactoryUpgradeable",
      await proxy.getAddress(),
    );
  }

  it("attempting to register an implementation as a non-owner should fail", async function () {
    const factory = await deployFactory();

    const implInfo = {
      implementation: "0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1",
      verifiers: {
        verifier: "0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1",
        batchVerifier: "0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1",
        depositVerifier: "0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1",
        withdrawVerifier: "0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1",
        batchWithdrawVerifier: "0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1",
        lockVerifier: "0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1",
        batchLockVerifier: "0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1",
        burnVerifier: "0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1",
        batchBurnVerifier: "0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1",
      },
    };
    await expect(
      factory.connect(nonOwner).registerImplementation("test", implInfo as any),
    ).rejectedWith(`reverted with custom error 'OwnableUnauthorizedAccount(`);
  });

  it("attempting to initialize twice should fail", async function () {
    const factory = await deployFactory();

    await expect(factory.initialize()).rejectedWith("InvalidInitialization");
  });

  it("attempting to register an implementation without the required implementation value should fail", async function () {
    const factory = await deployFactory();

    const implInfo = {
      implementation: "0x0000000000000000000000000000000000000000",
      verifiers: {
        verifier: "0x0000000000000000000000000000000000000000",
        batchVerifier: "0x0000000000000000000000000000000000000000",
        depositVerifier: "0x0000000000000000000000000000000000000000",
        withdrawVerifier: "0x0000000000000000000000000000000000000000",
        batchWithdrawVerifier: "0x0000000000000000000000000000000000000000",
        lockVerifier: "0x0000000000000000000000000000000000000000",
        batchLockVerifier: "0x0000000000000000000000000000000000000000",
        burnVerifier: "0x0000000000000000000000000000000000000000",
        batchBurnVerifier: "0x0000000000000000000000000000000000000000",
      },
    };
    await expect(
      factory.connect(deployer).registerImplementation("test", implInfo as any),
    ).rejectedWith("Factory: implementation address is required");
  });

  it("attempting to register an implementation without the required verifier value should fail", async function () {
    const factory = await deployFactory();

    const implInfo = {
      implementation: "0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1",
      verifiers: {
        verifier: "0x0000000000000000000000000000000000000000",
        batchVerifier: "0x0000000000000000000000000000000000000000",
        depositVerifier: "0x0000000000000000000000000000000000000000",
        withdrawVerifier: "0x0000000000000000000000000000000000000000",
        batchWithdrawVerifier: "0x0000000000000000000000000000000000000000",
        lockVerifier: "0x0000000000000000000000000000000000000000",
        batchLockVerifier: "0x0000000000000000000000000000000000000000",
        burnVerifier: "0x0000000000000000000000000000000000000000",
        batchBurnVerifier: "0x0000000000000000000000000000000000000000",
      },
    };
    await expect(
      factory.connect(deployer).registerImplementation("test", implInfo as any),
    ).rejectedWith("Factory: verifier address is required");
  });

  it("attempting to register an implementation with the required values should succeed", async function () {
    const factory = await deployFactory();

    const implInfo = {
      implementation: "0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1",
      verifiers: {
        verifier: "0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1",
        batchVerifier: "0x0000000000000000000000000000000000000000",
        depositVerifier: "0x0000000000000000000000000000000000000000",
        withdrawVerifier: "0x0000000000000000000000000000000000000000",
        batchWithdrawVerifier: "0x0000000000000000000000000000000000000000",
        lockVerifier: "0x0000000000000000000000000000000000000000",
        batchLockVerifier: "0x0000000000000000000000000000000000000000",
        burnVerifier: "0x0000000000000000000000000000000000000000",
        batchBurnVerifier: "0x0000000000000000000000000000000000000000",
      },
    };
    await expect(
      factory.connect(deployer).registerImplementation("test", implInfo as any),
    ).fulfilled;
  });

  it("attempting to deploy a fungible token but with a registered implementation that misses required batchVerifier should fail", async function () {
    const factory = await deployFactory();

    const implInfo = {
      implementation: "0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1",
      verifiers: {
        verifier: "0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1",
        batchVerifier: "0x0000000000000000000000000000000000000000",
        depositVerifier: "0x0000000000000000000000000000000000000000",
        withdrawVerifier: "0x0000000000000000000000000000000000000000",
        batchWithdrawVerifier: "0x0000000000000000000000000000000000000000",
        lockVerifier: "0x0000000000000000000000000000000000000000",
        batchLockVerifier: "0x0000000000000000000000000000000000000000",
        burnVerifier: "0x0000000000000000000000000000000000000000",
        batchBurnVerifier: "0x0000000000000000000000000000000000000000",
      },
    };
    const tx1 = await factory
      .connect(deployer)
      .registerImplementation("test", implInfo as any);
    await tx1.wait();

    await expect(
      factory
        .connect(deployer)
        .deployZetoFungibleToken(
          "name",
          "symbol",
          "test",
          await deployer.getAddress(),
        ),
    ).rejectedWith("Factory: depositVerifier address is required");
  });

  it("attempting to deploy a fungible token but with a registered implementation that misses required depositVerifier should fail", async function () {
    const factory = await deployFactory();

    const implInfo = {
      implementation: "0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1",
      verifiers: {
        verifier: "0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1",
        batchVerifier: "0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1",
        depositVerifier: "0x0000000000000000000000000000000000000000",
        withdrawVerifier: "0x0000000000000000000000000000000000000000",
        batchWithdrawVerifier: "0x0000000000000000000000000000000000000000",
        lockVerifier: "0x0000000000000000000000000000000000000000",
        batchLockVerifier: "0x0000000000000000000000000000000000000000",
        burnVerifier: "0x0000000000000000000000000000000000000000",
        batchBurnVerifier: "0x0000000000000000000000000000000000000000",
      },
    };
    const tx1 = await factory
      .connect(deployer)
      .registerImplementation("test", implInfo as any);
    await tx1.wait();

    await expect(
      factory
        .connect(deployer)
        .deployZetoFungibleToken(
          "name",
          "symbol",
          "test",
          await deployer.getAddress(),
        ),
    ).rejectedWith("Factory: depositVerifier address is required");
  });

  it("attempting to deploy a fungible token but with a registered implementation that misses required withdrawVerifier should fail", async function () {
    const factory = await deployFactory();

    const implInfo = {
      implementation: "0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1",
      verifiers: {
        verifier: "0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1",
        batchVerifier: "0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1",
        depositVerifier: "0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1",
        withdrawVerifier: "0x0000000000000000000000000000000000000000",
        batchWithdrawVerifier: "0x0000000000000000000000000000000000000000",
        lockVerifier: "0x0000000000000000000000000000000000000000",
        batchLockVerifier: "0x0000000000000000000000000000000000000000",
        burnVerifier: "0x0000000000000000000000000000000000000000",
        batchBurnVerifier: "0x0000000000000000000000000000000000000000",
      },
    };
    const tx1 = await factory
      .connect(deployer)
      .registerImplementation("test", implInfo as any);
    await tx1.wait();

    await expect(
      factory
        .connect(deployer)
        .deployZetoFungibleToken(
          "name",
          "symbol",
          "test",
          await deployer.getAddress(),
        ),
    ).rejectedWith("Factory: withdrawVerifier address is required");
  });

  it("attempting to deploy a fungible token but with a registered implementation that misses required batchWithdrawVerifier should fail", async function () {
    const factory = await deployFactory();

    const implInfo = {
      implementation: "0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1",
      verifiers: {
        verifier: "0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1",
        batchVerifier: "0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1",
        depositVerifier: "0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1",
        withdrawVerifier: "0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1",
        batchWithdrawVerifier: "0x0000000000000000000000000000000000000000",
        lockVerifier: "0x0000000000000000000000000000000000000000",
        batchLockVerifier: "0x0000000000000000000000000000000000000000",
        burnVerifier: "0x0000000000000000000000000000000000000000",
        batchBurnVerifier: "0x0000000000000000000000000000000000000000",
      },
    };
    const tx1 = await factory
      .connect(deployer)
      .registerImplementation("test", implInfo as any);
    await tx1.wait();

    await expect(
      factory
        .connect(deployer)
        .deployZetoFungibleToken(
          "name",
          "symbol",
          "test",
          await deployer.getAddress(),
        ),
    ).rejectedWith("Factory: batchWithdrawVerifier address is required");
  });

  it("attempting to deploy a fungible token with a properly registered implementation should succeed", async function () {
    const factory = await deployFactory();

    const implInfo = {
      implementation: "0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1",
      verifiers: {
        verifier: "0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1",
        batchVerifier: "0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1",
        depositVerifier: "0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1",
        withdrawVerifier: "0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1",
        batchWithdrawVerifier: "0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1",
        lockVerifier: "0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1",
        batchLockVerifier: "0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1",
        burnVerifier: "0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1",
        batchBurnVerifier: "0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1",
      },
    };
    const tx1 = await factory
      .connect(deployer)
      .registerImplementation("test", implInfo as any);
    await tx1.wait();

    await expect(
      factory
        .connect(deployer)
        .deployZetoFungibleToken(
          "name",
          "symbol",
          "test",
          await deployer.getAddress(),
        ),
    ).fulfilled;
  });
});
