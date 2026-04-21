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

import { ethers, network, upgrades } from "hardhat";
import {
  Signer,
  BigNumberish,
  AddressLike,
  ZeroAddress,
  AbiCoder,
  ContractTransactionReceipt,
} from "ethers";
import { expect } from "chai";
import { loadCircuit, encodeProof, Poseidon } from "zeto-js";
import { groth16 } from "snarkjs";
import { formatPrivKeyForBabyJub, stringifyBigInts } from "maci-crypto";
import {
  User,
  UTXO,
  newUser,
  newUTXO,
  doMint,
  parseUTXOEvents,
  ZERO_UTXO,
  logger,
} from "./lib/utils";
import {
  loadProvingKeys,
  prepareDepositProof,
  prepareWithdrawProof,
  prepareBurnProof,
  inflateUtxos,
  inflateOwners,
  calculateSpendHash,
  calculateCancelHash,
} from "./utils";
import { Zeto_Anon, Zeto_AnonBurnable } from "../typechain-types";
import { deployZeto } from "./lib/deploy";

const ZERO_PUBKEY = [0n, 0n];
const poseidonHash = Poseidon.poseidon4;

describe("Zeto based fungible token with anonymity without encryption or nullifier", function () {
  let deployer: Signer;
  let Alice: User;
  let Bob: User;
  let Charlie: User;
  let erc20: any;
  let zeto: Zeto_Anon;
  let zetoBurnable: Zeto_AnonBurnable;
  let utxo100: UTXO;
  let utxo1: UTXO;
  let utxo2: UTXO;
  let utxo3: UTXO;
  let utxo4: UTXO;
  let utxo7: UTXO;
  let circuit: any, provingKey: any;
  let batchCircuit: any, batchProvingKey: any;

  before(async function () {
    if (process.env.SKIP_ANON_TESTS === "true") {
      this.skip();
    }
    if (network.name !== "hardhat") {
      // accommodate for longer block times on public networks
      this.timeout(120000);
    }
    let [d, a, b, c] = await ethers.getSigners();
    deployer = d;
    Alice = await newUser(a);
    Bob = await newUser(b);
    Charlie = await newUser(c);

    ({ deployer, zeto, erc20 } = await deployZeto("Zeto_Anon"));
    ({ zeto: zetoBurnable } = await deployZeto("Zeto_AnonBurnable"));

    circuit = await loadCircuit("anon");
    ({ provingKeyFile: provingKey } = loadProvingKeys("anon"));

    batchCircuit = await loadCircuit("anon_batch");
    ({ provingKeyFile: batchProvingKey } = loadProvingKeys("anon_batch"));
  });

  beforeEach(async function () {
    if (process.env.SKIP_ANON_TESTS === "true") {
      this.skip();
    }
  });

  it("has 4 decimals", async function () {
    const decimals = await zeto.decimals();
    expect(decimals).to.equal(4, "Decimals should be 4");
  });

  it("non-owner should not be able to mint", async function () {
    const utxo1 = newUTXO(10, Alice);
    const utxo2 = newUTXO(20, Alice);
    await expect(doMint(zeto, Alice.signer, [utxo1, utxo2])).to.be.rejectedWith(
      "OwnableUnauthorizedAccount",
    );
  });

  // H-2: implementation contracts must be initialization-locked so an
  // attacker cannot call initialize() directly on the impl, become its
  // owner, and then upgradeTo(any) via _authorizeUpgrade (the OZ
  // "implementation takeover" pattern, CVE-2022-35961 family). We test
  // against the *actual deployed* implementation (read from the EIP-1967
  // impl slot on the proxy) so this asserts the production deployment
  // path produces a locked impl, not just that a redeployed contract
  // would be locked.
  it("initialize() reverts on the bare Zeto_Anon implementation contract", async function () {
    const implAddress = await upgrades.erc1967.getImplementationAddress(
      await zeto.getAddress(),
    );
    const impl = await ethers.getContractAt("Zeto_Anon", implAddress);
    await expect(
      impl.initialize("Z", "Z", await Alice.signer.getAddress(), {
        verifier: ZeroAddress,
        depositVerifier: ZeroAddress,
        withdrawVerifier: ZeroAddress,
        lockVerifier: ZeroAddress,
        burnVerifier: ZeroAddress,
        batchVerifier: ZeroAddress,
        batchWithdrawVerifier: ZeroAddress,
        batchLockVerifier: ZeroAddress,
        batchBurnVerifier: ZeroAddress,
      }),
    ).to.be.revertedWithCustomError(impl, "InvalidInitialization");
  });

  it("initialize() reverts on the bare Zeto_AnonBurnable implementation contract", async function () {
    const implAddress = await upgrades.erc1967.getImplementationAddress(
      await zetoBurnable.getAddress(),
    );
    const impl = await ethers.getContractAt("Zeto_AnonBurnable", implAddress);
    await expect(
      impl.initialize("Z", "Z", await Alice.signer.getAddress(), {
        verifier: ZeroAddress,
        depositVerifier: ZeroAddress,
        withdrawVerifier: ZeroAddress,
        lockVerifier: ZeroAddress,
        burnVerifier: ZeroAddress,
        batchVerifier: ZeroAddress,
        batchWithdrawVerifier: ZeroAddress,
        batchLockVerifier: ZeroAddress,
        batchBurnVerifier: ZeroAddress,
      }),
    ).to.be.revertedWithCustomError(impl, "InvalidInitialization");
  });

  describe("administrative invariants", function () {
    it("setERC20() rejects the zero address", async function () {
      // Use the burnable proxy as a stand-in: it has not had its ERC20
      // bound during deployZeto (only the non-burnable Zeto_Anon does),
      // so we are exercising the not-yet-set branch.
      await expect(zetoBurnable.connect(deployer).setERC20(ZeroAddress))
        .to.be.revertedWithCustomError(zetoBurnable, "ZeroERC20Address");
    });

    it("setERC20() is one-shot: a second call reverts with ERC20AlreadySet", async function () {
      // `zeto` already had setERC20(erc20) wired up in deployZeto, so the
      // backing token is bound. Any subsequent call -- even by the owner,
      // even to the same address -- must revert.
      const current = await erc20.getAddress();
      await expect(zeto.connect(deployer).setERC20(current))
        .to.be.revertedWithCustomError(zeto, "ERC20AlreadySet")
        .withArgs(current);
    });

    it("ownership transfer is two-step (Ownable2Step)", async function () {
      // Stage Alice as the pending owner. The current owner (deployer)
      // remains in control until Alice accepts.
      const aliceAddr = await Alice.signer.getAddress();
      const deployerAddr = await deployer.getAddress();
      await (await zeto.connect(deployer).transferOwnership(aliceAddr)).wait();
      expect(await zeto.owner()).to.equal(deployerAddr);
      expect(await zeto.pendingOwner()).to.equal(aliceAddr);

      // Anyone other than the pending owner accepting must revert.
      await expect(
        zeto.connect(Bob.signer).acceptOwnership(),
      ).to.be.revertedWithCustomError(zeto, "OwnableUnauthorizedAccount");

      // Alice accepts and the swap completes atomically.
      await (await zeto.connect(Alice.signer).acceptOwnership()).wait();
      expect(await zeto.owner()).to.equal(aliceAddr);

      // Restore the original owner so subsequent tests are unaffected.
      await (await zeto.connect(Alice.signer).transferOwnership(deployerAddr)).wait();
      await (await zeto.connect(deployer).acceptOwnership()).wait();
      expect(await zeto.owner()).to.equal(deployerAddr);
    });

    it("computeSpendHash() and computeCancelHash() live in disjoint hash spaces", async function () {
      // Defense-in-depth from M-7. Same payload must produce different
      // commitments under the spend-vs-cancel domain so a spender cannot
      // transpose a payload between spendLock and cancelLock.
      const utxo = newUTXO(1, Alice);
      const out = newUTXO(1, Bob);
      const lockedInputs = [utxo.hash];
      const lockedOutputs: bigint[] = [];
      const outputs = [out.hash];
      const data = "0x";
      const spend = await zeto.computeSpendHash(lockedInputs, lockedOutputs, outputs, data);
      const cancel = await zeto.computeCancelHash(lockedInputs, lockedOutputs, outputs, data);
      expect(spend).to.not.equal(cancel);
      // Mirror of off-chain helpers used by other tests.
      expect(spend).to.equal(calculateSpendHash([utxo], [], [out], data));
      expect(cancel).to.equal(calculateCancelHash([utxo], [], [out], data));
    });
  });

  describe("batch transfers", () => {
    let inputUtxos: UTXO[];
    let outputUtxos: UTXO[];
    let outputOwners: User[];
    let aliceUTXOsToBeWithdrawn: UTXO[];
    let txResult: ContractTransactionReceipt | null;

    it("mint to Alice 10 UTXOs", async () => {
      inputUtxos = [];
      for (let i = 0; i < 10; i++) {
        inputUtxos.push(newUTXO(1, Alice));
      }
      await doMint(zeto, deployer, inputUtxos);
    });

    it("transfer 10 UTXOs honestly to Bob & Charlie should succeed", async function () {
      aliceUTXOsToBeWithdrawn = [
        newUTXO(1, Alice),
        newUTXO(1, Alice),
        newUTXO(1, Alice),
      ];
      const _bOut1 = newUTXO(6, Bob);
      const _bOut2 = newUTXO(1, Charlie);

      outputUtxos = [_bOut1, _bOut2, ...aliceUTXOsToBeWithdrawn];
      outputOwners = [Bob, Charlie, Alice, Alice, Alice];

      txResult = await doTransfer(Alice, inputUtxos, outputUtxos, outputOwners);
    });

    it("check the non-empty output hashes are correct", async function () {
      const events = parseUTXOEvents(zeto, txResult);
      const incomingUTXOs: any = events[0].outputs;
      for (let i = 0; i < outputUtxos.length; i++) {
        const receivedValue = outputUtxos[i].value;
        const receivedSalt = outputUtxos[i].salt;
        const hash = poseidonHash([
          BigInt(receivedValue),
          receivedSalt,
          outputOwners[i].babyJubPublicKey[0],
          outputOwners[i].babyJubPublicKey[1],
        ]);
        expect(incomingUTXOs[i]).to.equal(hash);
      }
    });

    it("withdraw 3 UTXOs to ERC20 tokens", async function () {
      const mintTx = await erc20.connect(deployer).mint(zeto, 3);
      await mintTx.wait();
      const startingBalance = await erc20.balanceOf(Alice.ethAddress);

      const inflatedWithdrawInputs = [...aliceUTXOsToBeWithdrawn];
      for (let i = aliceUTXOsToBeWithdrawn.length; i < 10; i++) {
        inflatedWithdrawInputs.push(ZERO_UTXO);
      }
      const { inputCommitments, outputCommitments, encodedProof } =
        await prepareWithdrawProof(Alice, inflatedWithdrawInputs, ZERO_UTXO);

      const tx = await zeto
        .connect(Alice.signer)
        .withdraw(
          3,
          inputCommitments,
          outputCommitments[0],
          encodeToBytes(encodedProof),
          "0x",
        );
      await tx.wait();

      const endingBalance = await erc20.balanceOf(Alice.ethAddress);
      expect(endingBalance - startingBalance).to.be.equal(3);
    });
  });

  it("mint ERC20 tokens to Alice to deposit to Zeto should succeed", async function () {
    const startingBalance = await erc20.balanceOf(Alice.ethAddress);
    const tx = await erc20.connect(deployer).mint(Alice.ethAddress, 100);
    await tx.wait();
    const endingBalance = await erc20.balanceOf(Alice.ethAddress);
    expect(endingBalance - startingBalance).to.be.equal(100);

    const tx1 = await erc20.connect(Alice.signer).approve(zeto.target, 100);
    await tx1.wait();

    utxo100 = newUTXO(100, Alice);
    const utxo0 = newUTXO(0, Alice);
    const { outputCommitments, encodedProof } = await prepareDepositProof(
      Alice,
      [utxo100, utxo0],
    );
    const tx2 = await zeto
      .connect(Alice.signer)
      .deposit(100, outputCommitments, encodeToBytes(encodedProof), "0x");
    const result = await tx2.wait();
    logger.debug(`Method deposit() complete. Gas used: ${result?.gasUsed}`);
  });

  it("mint to Alice and transfer UTXOs honestly to Bob should succeed", async function () {
    this.timeout(60000);
    const startingBalance = await erc20.balanceOf(Alice.ethAddress);
    utxo1 = newUTXO(10, Alice);
    utxo2 = newUTXO(20, Alice);
    await doMint(zeto, deployer, [utxo1, utxo2]);

    const afterMintBalance = await erc20.balanceOf(Alice.ethAddress);
    expect(afterMintBalance).to.equal(startingBalance);

    const _txo3 = newUTXO(25, Bob);
    utxo4 = newUTXO(5, Alice, _txo3.salt);

    const result = await doTransfer(
      Alice,
      [utxo1, utxo2],
      [_txo3, utxo4],
      [Bob, Alice],
    );

    const afterTransferBalance = await erc20.balanceOf(Alice.ethAddress);
    expect(afterTransferBalance).to.equal(startingBalance);

    const events = parseUTXOEvents(zeto, result);
    const incomingUTXOs: any = events[0].outputs;
    const receivedValue = 25;
    const receivedSalt = _txo3.salt;
    const hash = poseidonHash([
      BigInt(receivedValue),
      receivedSalt,
      Bob.babyJubPublicKey[0],
      Bob.babyJubPublicKey[1],
    ]);
    expect(incomingUTXOs[0]).to.equal(hash);

    utxo3 = newUTXO(receivedValue, Bob, receivedSalt);
  });

  it("Bob transfers UTXOs, previously received from Alice, honestly to Charlie should succeed", async function () {
    const startingBalance = await erc20.balanceOf(Alice.ethAddress);
    const _utxo1 = newUTXO(20, Bob);
    await doMint(zeto, deployer, [_utxo1]);

    const afterMintBalance = await erc20.balanceOf(Alice.ethAddress);
    expect(afterMintBalance).to.equal(startingBalance);

    const _utxo2 = newUTXO(30, Charlie);
    utxo7 = newUTXO(15, Bob);

    await doTransfer(Bob, [utxo3, _utxo1], [_utxo2, utxo7], [Charlie, Bob]);

    const afterTransferBalance = await erc20.balanceOf(Alice.ethAddress);
    expect(afterTransferBalance).to.equal(startingBalance);
  });

  it("Alice withdraws her UTXOs to ERC20 tokens should succeed", async function () {
    const startingBalance = await erc20.balanceOf(Alice.ethAddress);

    const outputCommitment = newUTXO(20, Alice);

    const { inputCommitments, outputCommitments, encodedProof } =
      await prepareWithdrawProof(Alice, [utxo100, ZERO_UTXO], outputCommitment);

    const tx = await zeto
      .connect(Alice.signer)
      .withdraw(
        80,
        inputCommitments,
        outputCommitments[0],
        encodeToBytes(encodedProof),
        "0x",
      );
    const result = await tx.wait();
    logger.debug(`Method withdraw() complete. Gas used: ${result?.gasUsed}`);

    const endingBalance = await erc20.balanceOf(Alice.ethAddress);
    expect(endingBalance - startingBalance).to.be.equal(80);
  });

  it("Test support for large values, such as when using 18 decimals", async function () {
    const EighteenDecimals = 10 ** 18;

    const utxoA = newUTXO(10 * EighteenDecimals, Alice);
    const utxoB = newUTXO(20 * EighteenDecimals, Alice);
    await doMint(zeto, deployer, [utxoA, utxoB]);

    const utxoC = newUTXO(25 * EighteenDecimals, Bob);
    const utxoD = newUTXO(5 * EighteenDecimals, Alice);

    const result = await doTransfer(
      Alice,
      [utxoA, utxoB],
      [utxoC, utxoD],
      [Bob, Alice],
    );

    const events = parseUTXOEvents(zeto, result);
    const incomingUTXOs: any = events[0].outputs;
    const receivedValue = 25 * EighteenDecimals;
    const receivedSalt = utxoC.salt;
    const hash = poseidonHash([
      BigInt(receivedValue),
      receivedSalt,
      Bob.babyJubPublicKey[0],
      Bob.babyJubPublicKey[1],
    ]);
    expect(incomingUTXOs[0]).to.equal(hash);
  });

  describe("failure cases", function () {
    // the following failure cases rely on the hardhat network
    // to return the details of the errors. This is not possible
    // on non-hardhat networks
    if (network.name !== "hardhat") {
      return;
    }

    it("Alice attempting to withdraw spent UTXOs should fail", async function () {
      const outputCommitment = newUTXO(90, Alice);

      const { inputCommitments, outputCommitments, encodedProof } =
        await prepareWithdrawProof(
          Alice,
          [utxo100, ZERO_UTXO],
          outputCommitment,
        );

      await expect(
        zeto
          .connect(Alice.signer)
          .withdraw(
            10,
            inputCommitments,
            outputCommitments[0],
            encodeToBytes(encodedProof),
            "0x",
          ),
      ).rejectedWith("UTXOAlreadySpent");
    });

    it("mint existing unspent UTXOs should fail", async function () {
      await expect(doMint(zeto, deployer, [utxo4])).rejectedWith(
        "UTXOAlreadyOwned",
      );
    });

    it("mint existing spent UTXOs should fail", async function () {
      await expect(doMint(zeto, deployer, [utxo1])).rejectedWith(
        "UTXOAlreadySpent",
      );
    });

    it("transfer non-existing UTXOs should fail", async function () {
      const nonExisting1 = newUTXO(10, Alice);
      const nonExisting2 = newUTXO(20, Alice, nonExisting1.salt);
      await expect(
        doTransfer(
          Alice,
          [nonExisting1, nonExisting2],
          [nonExisting1, nonExisting2],
          [Alice, Alice],
        ),
      ).rejectedWith("UTXONotMinted");
    });

    it("transfer spent UTXOs should fail (double spend protection)", async function () {
      const utxo5 = newUTXO(25, Bob);
      const utxo6 = newUTXO(5, Alice, utxo5.salt);
      await expect(
        doTransfer(Alice, [utxo1, utxo2], [utxo5, utxo6], [Bob, Alice]),
      ).rejectedWith("UTXOAlreadySpent");
    });

    it("spend by using the same UTXO as both inputs should fail", async function () {
      const utxo5 = newUTXO(20, Alice);
      const utxo6 = newUTXO(10, Bob, utxo5.salt);
      await expect(
        doTransfer(Bob, [utxo7, utxo7], [utxo5, utxo6], [Alice, Bob]),
      ).rejectedWith(`UTXODuplicate(${utxo7.hash.toString()}`);
    });
  });

  describe("ILockableCapability tests", function () {
    // ABI fragments for the ZetoLockableCapability *Args payloads. Mirrors
    // the layout used in zeto_anon_nullifier.ts so that the cross-token
    // contract surface stays uniform.
    const CREATE_ARGS_ABI =
      "tuple(bytes32 txId, uint256[] inputs, uint256[] outputs, uint256[] lockedOutputs, bytes proof)";
    const UPDATE_ARGS_ABI = "tuple(bytes32 txId)";
    const DELEGATE_ARGS_ABI = "tuple(bytes32 txId)";
    const SPEND_ARGS_ABI =
      "tuple(bytes32 txId, uint256[] lockedOutputs, uint256[] outputs, bytes proof, bytes data)";

    function encodeCreateArgs(args: {
      txId: string;
      inputs: BigNumberish[];
      outputs: BigNumberish[];
      lockedOutputs: BigNumberish[];
      proof: string;
    }) {
      return new AbiCoder().encode([CREATE_ARGS_ABI], [args]);
    }

    function encodeUpdateArgs(txId: string) {
      return new AbiCoder().encode([UPDATE_ARGS_ABI], [{ txId }]);
    }

    function encodeDelegateArgs(txId: string) {
      return new AbiCoder().encode([DELEGATE_ARGS_ABI], [{ txId }]);
    }

    function encodeSpendArgs(args: {
      txId: string;
      lockedOutputs: BigNumberish[];
      outputs: BigNumberish[];
      proof: string;
      data: string;
    }) {
      return new AbiCoder().encode([SPEND_ARGS_ABI], [args]);
    }

    function randomBytes32(): string {
      return ethers.hexlify(ethers.randomBytes(32));
    }

    describe("createLock -> updateLock -> delegateLock -> spendLock flow", function () {
      let bobSourceUtxo: UTXO;
      let lockedUtxo: UTXO;
      let lockId: string;
      let outUtxo1: UTXO;
      let outUtxo2: UTXO;
      let unlockHash: string;

      before(async function () {
        bobSourceUtxo = newUTXO(100, Bob);
        await doMint(zeto, deployer, [bobSourceUtxo]);
      });

      it("createLock() with deterministic lockId computed from txId", async function () {
        // The locked content is just a fresh UTXO of equal value held under Bob.
        // The proof on the create path proves the standard transfer
        // relationship: bobSourceUtxo  ->  lockedUtxo. The contract treats
        // the locked output identically to a regular output for the purposes
        // of circuit verification (they are merged into a single output set
        // before constructPublicInputs), so the same anon circuit is reused.
        lockedUtxo = newUTXO(bobSourceUtxo.value!, Bob);
        const encodedZkProof = await prepareProof(
          circuit,
          provingKey,
          Bob,
          [bobSourceUtxo, ZERO_UTXO],
          [lockedUtxo, ZERO_UTXO],
          [Bob, Bob],
        );

        const txId = randomBytes32();
        const createArgs = encodeCreateArgs({
          txId,
          inputs: [bobSourceUtxo.hash],
          outputs: [],
          lockedOutputs: [lockedUtxo.hash],
          proof: encodeToBytes(encodedZkProof),
        });

        const predicted = await zeto
          .connect(Bob.signer)
          .computeLockId(createArgs);
        lockId = predicted;

        const tx = await zeto
          .connect(Bob.signer)
          .createLock(createArgs, ethers.ZeroHash, ethers.ZeroHash, "0x");
        const result: ContractTransactionReceipt | null = await tx.wait();
        logger.debug(`createLock() complete. Gas used: ${result?.gasUsed}`);

        const created = result!.logs
          .map((l) => {
            try {
              return zeto.interface.parseLog(l as any);
            } catch (_e) {
              return null;
            }
          })
          .find((p) => p && p.name === "LockCreated");
        expect(created, "LockCreated event not found").to.not.be.null;
        expect(created!.args.lockId).to.equal(predicted);
        expect(created!.args.owner).to.equal(Bob.ethAddress);
        expect(created!.args.spender).to.equal(Bob.ethAddress);
      });

      it("isLockActive() and getLock() reflect the newly created lock", async function () {
        expect(await zeto.isLockActive(lockId)).to.equal(true);
        const info = await zeto.getLock(lockId);
        expect(info.owner).to.equal(Bob.ethAddress);
        expect(info.spender).to.equal(Bob.ethAddress);
        expect(info.spendCommitment).to.equal(ethers.ZeroHash);
        expect(info.cancelCommitment).to.equal(ethers.ZeroHash);
      });

      it("locked() returns true for locked UTXOs and false for unlocked or spent UTXOs", async function () {
        // Just-created lock: spender == owner == Bob.
        expect(await zeto.locked(lockedUtxo.hash)).to.deep.equal([
          true,
          Bob.ethAddress,
        ]);
        expect((await zeto.locked(bobSourceUtxo.hash))[0]).to.be.false;
      });

      it("updateLock() commits the spend hash while owner == spender", async function () {
        outUtxo1 = newUTXO(10, Alice);
        outUtxo2 = newUTXO(90, Bob);

        unlockHash = calculateSpendHash(
          [lockedUtxo],
          [],
          [outUtxo1, outUtxo2],
          "0x",
        );

        const tx = await zeto
          .connect(Bob.signer)
          .updateLock(
            lockId,
            encodeUpdateArgs(randomBytes32()),
            unlockHash,
            ethers.ZeroHash,
            "0x",
          );
        const result = await tx.wait();
        logger.debug(`updateLock() complete. Gas used: ${result?.gasUsed}`);

        const info = await zeto.getLock(lockId);
        expect(info.spendCommitment).to.equal(unlockHash);
      });

      it("delegateLock() transfers spending authority to Alice", async function () {
        const tx = await zeto
          .connect(Bob.signer)
          .delegateLock(
            lockId,
            encodeDelegateArgs(randomBytes32()),
            Alice.ethAddress,
            "0x",
          );
        const result = await tx.wait();
        logger.debug(`delegateLock() complete. Gas used: ${result?.gasUsed}`);

        const info = await zeto.getLock(lockId);
        expect(info.spender).to.equal(Alice.ethAddress);
        // Per-UTXO delegate projection in ZetoFungible must reflect the
        // new spender. This is the layer that BaseStorage no longer tracks
        // after the "pull delegates out of BaseStorage" refactor.
        expect(await zeto.locked(lockedUtxo.hash)).to.deep.equal([
          true,
          Alice.ethAddress,
        ]);
      });

      it("the new spender can spendLock() with the matching payload", async function () {
        const encodedZkProofForSettle = await prepareProof(
          circuit,
          provingKey,
          Bob,
          [lockedUtxo, ZERO_UTXO],
          [outUtxo1, outUtxo2],
          [Alice, Bob],
        );

        const spendArgs = encodeSpendArgs({
          txId: randomBytes32(),
          lockedOutputs: [],
          outputs: [outUtxo1.hash, outUtxo2.hash],
          proof: encodeToBytes(encodedZkProofForSettle),
          data: "0x",
        });

        const tx = await zeto
          .connect(Alice.signer)
          .spendLock(lockId, spendArgs, "0x");
        const result = await tx.wait();

        const parsed = result!.logs
          .map((l) => {
            try {
              return zeto.interface.parseLog(l as any);
            } catch (_e) {
              return null;
            }
          })
          .filter((p) => p !== null) as ReadonlyArray<{
          name: string;
          args: any;
        }>;
        const lockSpent = parsed.find((p) => p.name === "LockSpent");
        const zetoLockSpent = parsed.find((p) => p.name === "ZetoLockSpent");
        expect(lockSpent, "LockSpent event not emitted").to.not.be.undefined;
        expect(zetoLockSpent, "ZetoLockSpent event not emitted").to.not.be
          .undefined;
        expect(lockSpent!.args.lockId).to.equal(lockId);
        expect(lockSpent!.args.spender).to.equal(Alice.ethAddress);

        // Lock is no longer active.
        expect(await zeto.isLockActive(lockId)).to.equal(false);

        // Outputs are now ordinary unlocked UTXOs.
        expect(await zeto.spent(outUtxo1.hash)).to.equal(1n); // UNSPENT
        expect(await zeto.spent(outUtxo2.hash)).to.equal(1n); // UNSPENT

        // Per-UTXO delegate projection is cleared post-consume.
        expect(await zeto.locked(lockedUtxo.hash)).to.deep.equal([
          false,
          ZeroAddress,
        ]);
      });
    });

    describe("createLock -> cancelLock flow", function () {
      let bobSourceUtxo: UTXO;
      let lockedUtxo: UTXO;
      let lockId: string;
      let cancelHash: string;
      let outUtxo1: UTXO;
      let outUtxo2: UTXO;

      before(async function () {
        bobSourceUtxo = newUTXO(100, Bob);
        await doMint(zeto, deployer, [bobSourceUtxo]);
      });

      it("Bob createLock() with a non-zero cancelCommitment", async function () {
        lockedUtxo = newUTXO(bobSourceUtxo.value!, Bob);
        const encodedZkProof = await prepareProof(
          circuit,
          provingKey,
          Bob,
          [bobSourceUtxo, ZERO_UTXO],
          [lockedUtxo, ZERO_UTXO],
          [Bob, Bob],
        );

        outUtxo1 = newUTXO(10, Alice);
        outUtxo2 = newUTXO(90, Bob);
        cancelHash = calculateCancelHash(
          [lockedUtxo],
          [],
          [outUtxo1, outUtxo2],
          "0x",
        );

        const createArgs = encodeCreateArgs({
          txId: randomBytes32(),
          inputs: [bobSourceUtxo.hash],
          outputs: [],
          lockedOutputs: [lockedUtxo.hash],
          proof: encodeToBytes(encodedZkProof),
        });
        lockId = await zeto.connect(Bob.signer).computeLockId(createArgs);
        const tx = await zeto
          .connect(Bob.signer)
          .createLock(createArgs, ethers.ZeroHash, cancelHash, "0x");
        const result = await tx.wait();
        logger.debug(`createLock() complete. Gas used: ${result?.gasUsed}`);
      });

      it("the owner can cancelLock() to reverse the lock without delegation", async function () {
        const encodedZkProofForCancel = await prepareProof(
          circuit,
          provingKey,
          Bob,
          [lockedUtxo, ZERO_UTXO],
          [outUtxo1, outUtxo2],
          [Alice, Bob],
        );

        const cancelArgs = encodeSpendArgs({
          txId: randomBytes32(),
          lockedOutputs: [],
          outputs: [outUtxo1.hash, outUtxo2.hash],
          proof: encodeToBytes(encodedZkProofForCancel),
          data: "0x",
        });

        const tx = await zeto
          .connect(Bob.signer)
          .cancelLock(lockId, cancelArgs, "0x");
        const result = await tx.wait();

        const parsed = result!.logs
          .map((l) => {
            try {
              return zeto.interface.parseLog(l as any);
            } catch (_e) {
              return null;
            }
          })
          .filter((p) => p !== null) as ReadonlyArray<{
          name: string;
          args: any;
        }>;
        const cancelled = parsed.find((p) => p.name === "LockCancelled");
        const zetoCancelled = parsed.find((p) => p.name === "ZetoLockCancelled");
        expect(cancelled, "LockCancelled event not emitted").to.not.be.undefined;
        expect(zetoCancelled, "ZetoLockCancelled event not emitted").to.not.be
          .undefined;

        expect(await zeto.isLockActive(lockId)).to.equal(false);
      });
    });

    describe("spendLock with a payload that does not match the spend commitment fails", function () {
      let bobSourceUtxo: UTXO;
      let lockedUtxo: UTXO;
      let lockId: string;
      let expectedHash: string;

      before(async function () {
        bobSourceUtxo = newUTXO(100, Bob);
        await doMint(zeto, deployer, [bobSourceUtxo]);
      });

      it("Bob createLock() then updateLock() committing a specific spend hash", async function () {
        lockedUtxo = newUTXO(bobSourceUtxo.value!, Bob);
        const encodedZkProof = await prepareProof(
          circuit,
          provingKey,
          Bob,
          [bobSourceUtxo, ZERO_UTXO],
          [lockedUtxo, ZERO_UTXO],
          [Bob, Bob],
        );
        const createArgs = encodeCreateArgs({
          txId: randomBytes32(),
          inputs: [bobSourceUtxo.hash],
          outputs: [],
          lockedOutputs: [lockedUtxo.hash],
          proof: encodeToBytes(encodedZkProof),
        });
        lockId = await zeto.connect(Bob.signer).computeLockId(createArgs);
        await (
          await zeto
            .connect(Bob.signer)
            .createLock(createArgs, ethers.ZeroHash, ethers.ZeroHash, "0x")
        ).wait();

        const expectedOut1 = newUTXO(10, Alice);
        const expectedOut2 = newUTXO(90, Bob);
        expectedHash = calculateSpendHash(
          [lockedUtxo],
          [],
          [expectedOut1, expectedOut2],
          "0x",
        );
        await (
          await zeto
            .connect(Bob.signer)
            .updateLock(
              lockId,
              encodeUpdateArgs(randomBytes32()),
              expectedHash,
              ethers.ZeroHash,
              "0x",
            )
        ).wait();
      });

      it("spendLock() with a different payload reverts with InvalidUnlockHash", async function () {
        if (network.name !== "hardhat") {
          this.skip();
        }
        const wrongOut1 = newUTXO(20, Alice);
        const wrongOut2 = newUTXO(80, Bob);

        const encodedZkProofForSettle = await prepareProof(
          circuit,
          provingKey,
          Bob,
          [lockedUtxo, ZERO_UTXO],
          [wrongOut1, wrongOut2],
          [Alice, Bob],
        );

        const spendArgs = encodeSpendArgs({
          txId: randomBytes32(),
          lockedOutputs: [],
          outputs: [wrongOut1.hash, wrongOut2.hash],
          proof: encodeToBytes(encodedZkProofForSettle),
          data: "0x",
        });

        const calculatedHash = calculateSpendHash(
          [lockedUtxo],
          [],
          [wrongOut1, wrongOut2],
          "0x",
        );

        await expect(
          zeto.connect(Bob.signer).spendLock(lockId, spendArgs, "0x"),
        )
          .to.be.revertedWithCustomError(zeto, "InvalidUnlockHash")
          .withArgs(expectedHash, calculatedHash);
      });
    });

    describe("negative cases for the lock lifecycle", function () {
      // These tests rely on hardhat-style revert decoding.
      if (network.name !== "hardhat") {
        return;
      }

      // freshLock mints a UTXO for `owner`, locks it, and returns the
      // resulting lock metadata so each negative case can branch off
      // without polluting other test scopes.
      async function freshLock(
        owner: User,
        spendCommitment: string = ethers.ZeroHash,
        cancelCommitment: string = ethers.ZeroHash,
      ): Promise<{
        lockId: string;
        sourceUtxo: UTXO;
        lockedUtxo: UTXO;
        createArgs: string;
      }> {
        const sourceUtxo = newUTXO(100, owner);
        await doMint(zeto, deployer, [sourceUtxo]);

        const lockedUtxo = newUTXO(sourceUtxo.value!, owner);
        const encodedZkProof = await prepareProof(
          circuit,
          provingKey,
          owner,
          [sourceUtxo, ZERO_UTXO],
          [lockedUtxo, ZERO_UTXO],
          [owner, owner],
        );

        const createArgs = encodeCreateArgs({
          txId: randomBytes32(),
          inputs: [sourceUtxo.hash],
          outputs: [],
          lockedOutputs: [lockedUtxo.hash],
          proof: encodeToBytes(encodedZkProof),
        });
        const lockId = await zeto
          .connect(owner.signer)
          .computeLockId(createArgs);
        await (
          await zeto
            .connect(owner.signer)
            .createLock(createArgs, spendCommitment, cancelCommitment, "0x")
        ).wait();
        return { lockId, sourceUtxo, lockedUtxo, createArgs };
      }

      // Re-encoding helper: a syntactically valid spend payload that does
      // NOT need to verify a real ZK proof. Tests for authorization /
      // immutability assertions short-circuit before the proof is touched.
      function dummySpendArgs(): string {
        return encodeSpendArgs({
          txId: randomBytes32(),
          lockedOutputs: [],
          outputs: [],
          proof: "0x",
          data: "0x",
        });
      }

      it("createLock() with a duplicate txId from the same caller reverts with DuplicateLock", async function () {
        const { lockId, createArgs } = await freshLock(Bob);

        // Same createArgs (same txId, same caller) => same lockId =>
        // DuplicateLock fires before any input or proof validation.
        await expect(
          zeto
            .connect(Bob.signer)
            .createLock(createArgs, ethers.ZeroHash, ethers.ZeroHash, "0x"),
        )
          .to.be.revertedWithCustomError(zeto, "DuplicateLock")
          .withArgs(lockId);
      });

      it("updateLock() by a non-owner reverts with LockUnauthorized", async function () {
        const { lockId } = await freshLock(Bob);

        await expect(
          zeto
            .connect(Alice.signer)
            .updateLock(
              lockId,
              encodeUpdateArgs(randomBytes32()),
              ethers.ZeroHash,
              ethers.ZeroHash,
              "0x",
            ),
        )
          .to.be.revertedWithCustomError(zeto, "LockUnauthorized")
          .withArgs(lockId, Bob.ethAddress, Alice.ethAddress);
      });

      it("updateLock() prefers LockUnauthorized over LockImmutable when both apply (M-5)", async function () {
        // Lock is delegated (so spender != owner -> immutable) AND the
        // caller is neither owner nor spender. The contract MUST report
        // LockUnauthorized, not leak the immutability state to the
        // unauthorized caller.
        const { lockId } = await freshLock(Bob);
        await (
          await zeto
            .connect(Bob.signer)
            .delegateLock(
              lockId,
              encodeDelegateArgs(randomBytes32()),
              Alice.ethAddress,
              "0x",
            )
        ).wait();

        await expect(
          zeto
            .connect(Charlie.signer)
            .updateLock(
              lockId,
              encodeUpdateArgs(randomBytes32()),
              ethers.ZeroHash,
              ethers.ZeroHash,
              "0x",
            ),
        )
          .to.be.revertedWithCustomError(zeto, "LockUnauthorized")
          // spender at this point is Alice (the new delegate).
          .withArgs(lockId, Alice.ethAddress, Charlie.ethAddress);
      });

      it("updateLock() after delegateLock() reverts with LockImmutable", async function () {
        const { lockId } = await freshLock(Bob);

        // Bob delegates spending authority to Alice; spender (Alice) now
        // differs from owner (Bob).
        await (
          await zeto
            .connect(Bob.signer)
            .delegateLock(
              lockId,
              encodeDelegateArgs(randomBytes32()),
              Alice.ethAddress,
              "0x",
            )
        ).wait();

        // Even Bob (the owner) can no longer mutate the commitments —
        // the lock is now externally controlled and must be considered
        // immutable.
        await expect(
          zeto
            .connect(Bob.signer)
            .updateLock(
              lockId,
              encodeUpdateArgs(randomBytes32()),
              ethers.ZeroHash,
              ethers.ZeroHash,
              "0x",
            ),
        )
          .to.be.revertedWithCustomError(zeto, "LockImmutable")
          .withArgs(lockId);
      });

      it("delegateLock() by a non-spender reverts with LockUnauthorized", async function () {
        const { lockId } = await freshLock(Bob);

        await expect(
          zeto
            .connect(Alice.signer)
            .delegateLock(
              lockId,
              encodeDelegateArgs(randomBytes32()),
              Charlie.ethAddress,
              "0x",
            ),
        )
          .to.be.revertedWithCustomError(zeto, "LockUnauthorized")
          .withArgs(lockId, Bob.ethAddress, Alice.ethAddress);
      });

      it("spendLock() by a non-spender reverts with LockUnauthorized before touching the proof", async function () {
        const { lockId } = await freshLock(Bob);

        // Garbage proof — the onlySpender modifier MUST short-circuit
        // before any proof verification is attempted.
        await expect(
          zeto.connect(Alice.signer).spendLock(lockId, dummySpendArgs(), "0x"),
        )
          .to.be.revertedWithCustomError(zeto, "LockUnauthorized")
          .withArgs(lockId, Bob.ethAddress, Alice.ethAddress);
      });

      it("cancelLock() by a non-spender reverts with LockUnauthorized", async function () {
        const { lockId } = await freshLock(Bob);

        await expect(
          zeto.connect(Alice.signer).cancelLock(lockId, dummySpendArgs(), "0x"),
        )
          .to.be.revertedWithCustomError(zeto, "LockUnauthorized")
          .withArgs(lockId, Bob.ethAddress, Alice.ethAddress);
      });

      it("after a successful spendLock(), the lock is no longer active and getLock() reverts", async function () {
        const { lockId, lockedUtxo } = await freshLock(Bob);

        const out1 = newUTXO(10, Alice);
        const out2 = newUTXO(90, Bob);
        const zkProof = await prepareProof(
          circuit,
          provingKey,
          Bob,
          [lockedUtxo, ZERO_UTXO],
          [out1, out2],
          [Alice, Bob],
        );
        const spendArgs = encodeSpendArgs({
          txId: randomBytes32(),
          lockedOutputs: [],
          outputs: [out1.hash, out2.hash],
          proof: encodeToBytes(zkProof),
          data: "0x",
        });
        await (
          await zeto.connect(Bob.signer).spendLock(lockId, spendArgs, "0x")
        ).wait();

        expect(await zeto.isLockActive(lockId)).to.equal(false);
        await expect(zeto.getLock(lockId))
          .to.be.revertedWithCustomError(zeto, "LockNotActive")
          .withArgs(lockId);
        // Re-spending a consumed lock MUST also fail — lockActive is
        // the first modifier and emits LockNotActive before
        // onlySpender has a chance to fire.
        await expect(
          zeto.connect(Bob.signer).spendLock(lockId, dummySpendArgs(), "0x"),
        )
          .to.be.revertedWithCustomError(zeto, "LockNotActive")
          .withArgs(lockId);
      });

      it("an unlocked input flow rejects a locked UTXO with AlreadyLocked", async function () {
        // Mint a UTXO, lock it, then try to spend it via the regular
        // transfer path. The base-storage validateInputs() guards this
        // and reverts with AlreadyLocked on the locked input.
        const { lockedUtxo } = await freshLock(Bob);

        await expect(
          doTransfer(
            Bob,
            [lockedUtxo, ZERO_UTXO],
            [newUTXO(100, Alice), ZERO_UTXO],
            [Alice, Alice],
          ),
        )
          .to.be.revertedWithCustomError(zeto, "AlreadyLocked")
          .withArgs(lockedUtxo.hash);
      });
    });
  });

  async function doTransfer(
    signer: User,
    inputs: UTXO[],
    outputs: UTXO[],
    owners: User[],
  ) {
    let inputCommitments: BigNumberish[];
    let outputCommitments: BigNumberish[];
    let outputOwnerAddresses: AddressLike[];
    let encodedProof: any;
    let circuitToUse = circuit;
    let provingKeyToUse = provingKey;
    if (inputs.length > 2 || outputs.length > 2) {
      circuitToUse = batchCircuit;
      provingKeyToUse = batchProvingKey;
    }
    const inflatedInputUtxos = inflateUtxos(inputs);
    const inflatedOutputUtxos = inflateUtxos(outputs);
    const inflatedOwners = inflateOwners(owners);

    encodedProof = await prepareProof(
      circuitToUse,
      provingKeyToUse,
      signer,
      inflatedInputUtxos,
      inflatedOutputUtxos,
      inflatedOwners,
    );
    inputCommitments = inputs.map((input) => input.hash);
    outputCommitments = outputs.map((output) => output.hash);
    outputOwnerAddresses = owners.map(
      (owner) => owner.ethAddress || ZeroAddress,
    ) as [AddressLike, AddressLike];

    return await sendTx(
      signer,
      inputCommitments,
      outputCommitments,
      encodedProof,
    );
  }

  async function sendTx(
    signer: User,
    inputCommitments: BigNumberish[],
    outputCommitments: BigNumberish[],
    encodedProof: any,
  ) {
    const proof = encodeToBytes(encodedProof);
    const tx = await zeto
      .connect(signer.signer)
      .transfer(inputCommitments, outputCommitments, proof, "0x");
    const results = await tx.wait();
    logger.debug(`Method transfer() complete. Gas used: ${results?.gasUsed}`);

    for (const input of inputCommitments) {
      if (input === 0n) {
        continue;
      }
      const status = await zeto.spent(input);
      expect(status).to.equal(2n); // UTXOStatus.SPENT
    }
    for (const output of outputCommitments) {
      if (output === 0n) {
        continue;
      }
      const status = await zeto.spent(output);
      expect(status).to.equal(1n); // UTXOStatus.UNSPENT
    }

    return results;
  }

  describe("Zeto_AnonBurnable", function () {
    it("(burnable) mint to Alice and burn a subset should succeed", async function () {
      const inputUtxos = [];
      for (let i = 0; i < 3; i++) {
        inputUtxos.push(newUTXO(10, Alice));
      }
      await doMint(zetoBurnable, deployer, inputUtxos);

      const remainder = newUTXO(5, Alice);

      const { inputCommitments, outputCommitment, encodedProof } =
        await prepareBurnProof(Alice, inputUtxos.slice(0, 2), remainder);
      const tx = await zetoBurnable
        .connect(Alice.signer)
        .burn(inputCommitments, outputCommitment, encodedProof, "0x");
      const result = await tx.wait();
      logger.debug(`Method burn() complete. Gas used: ${result?.gasUsed}`);

      let spent = await zetoBurnable.spent(inputCommitments[0]);
      expect(spent).to.equal(2n); // UTXOStatus.SPENT
      spent = await zetoBurnable.spent(inputCommitments[1]);
      expect(spent).to.equal(2n); // UTXOStatus.SPENT
      spent = await zetoBurnable.spent(inputUtxos[2].hash as BigNumberish);
      expect(spent).to.equal(1n); // UTXOStatus.UNSPENT
      spent = await zetoBurnable.spent(outputCommitment);
      expect(spent).to.equal(1n); // UTXOStatus.UNSPENT (the burn remainder)
    });

    it("burn rejects already-spent inputs", async function () {
      const inputUtxos = [newUTXO(10, Alice), newUTXO(10, Alice)];
      await doMint(zetoBurnable, deployer, inputUtxos);

      const remainder1 = newUTXO(5, Alice);
      const proof1 = await prepareBurnProof(Alice, inputUtxos, remainder1);
      await zetoBurnable
        .connect(Alice.signer)
        .burn(
          proof1.inputCommitments,
          proof1.outputCommitment,
          proof1.encodedProof,
          "0x",
        );

      const remainder2 = newUTXO(5, Alice);
      const proof2 = await prepareBurnProof(Alice, inputUtxos, remainder2);
      await expect(
        zetoBurnable
          .connect(Alice.signer)
          .burn(
            proof2.inputCommitments,
            proof2.outputCommitment,
            proof2.encodedProof,
            "0x",
          ),
      ).to.be.rejectedWith("UTXOAlreadySpent");
    });
  });
});

async function prepareProof(
  circuit: any,
  provingKey: any,
  signer: User,
  inputs: UTXO[],
  outputs: UTXO[],
  owners: User[],
) {
  const inputCommitments: BigNumberish[] = inputs.map(
    (input) => input.hash,
  ) as BigNumberish[];
  const inputValues = inputs.map((input) => BigInt(input.value || 0n));
  const inputSalts = inputs.map((input) => input.salt || 0n);
  const outputCommitments: BigNumberish[] = outputs.map(
    (output) => output.hash,
  ) as BigNumberish[];
  const outputValues = outputs.map((output) => BigInt(output.value || 0n));
  const outputSalts = outputs.map((o) => o.salt || 0n);
  const outputOwnerPublicKeys: BigNumberish[][] = owners.map(
    (owner) => owner.babyJubPublicKey || ZERO_PUBKEY,
  ) as BigNumberish[][];
  const otherInputs = stringifyBigInts({
    inputOwnerPrivateKey: formatPrivKeyForBabyJub(signer.babyJubPrivateKey),
  });

  const startWitnessCalculation = Date.now();
  const witness = await circuit.calculateWTNSBin(
    {
      inputCommitments,
      inputValues,
      inputSalts,
      outputCommitments,
      outputValues,
      outputSalts,
      outputOwnerPublicKeys,
      ...otherInputs,
    },
    true,
  );
  const timeWitnessCalculation = Date.now() - startWitnessCalculation;

  const startProofGeneration = Date.now();
  const { proof, publicSignals } = (await groth16.prove(
    provingKey,
    witness,
  )) as { proof: BigNumberish[]; publicSignals: BigNumberish[] };
  const timeProofGeneration = Date.now() - startProofGeneration;
  logger.debug(
    `Witness calculation time: ${timeWitnessCalculation}ms, Proof generation time: ${timeProofGeneration}ms`,
  );
  const encodedProof = encodeProof(proof);
  return encodedProof;
}

function encodeToBytes(proof: any) {
  return new AbiCoder().encode(
    ["tuple(uint256[2] pA, uint256[2][2] pB, uint256[2] pC)"],
    [proof],
  );
}

module.exports = {
  prepareProof,
  encodeToBytes,
};
