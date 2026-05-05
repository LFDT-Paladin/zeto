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

import { ethers, network } from "hardhat";
import {
  Signer,
  BigNumberish,
  AddressLike,
  AbiCoder,
  ZeroAddress,
  ContractTransactionReceipt,
} from "ethers";
import { expect } from "chai";
import { loadCircuit, tokenUriHash, encodeProof } from "zeto-js";
import { groth16 } from "snarkjs";
import { formatPrivKeyForBabyJub, stringifyBigInts } from "maci-crypto";
import {
  User,
  UTXO,
  newUser,
  newAssetUTXO,
  doMint,
  logger,
} from "./lib/utils";
import {
  loadProvingKeys,
  calculateSpendHash,
  calculateCancelHash,
} from "./utils";
import { deployZeto } from "./lib/deploy";

describe("Zeto based non-fungible token with anonymity without encryption or nullifiers", function () {
  let deployer: Signer;
  let Alice: User;
  let Bob: User;
  let Charlie: User;
  let zeto: any;
  let utxo1: UTXO;
  let utxo2: UTXO;
  let utxo3: UTXO;
  let circuit: any, provingKey: any;

  before(async function () {
    if (network.name !== "hardhat") {
      // accommodate for longer block times on public networks
      this.timeout(120000);
    }
    let [d, a, b, c] = await ethers.getSigners();
    deployer = d;
    Alice = await newUser(a);
    Bob = await newUser(b);
    Charlie = await newUser(c);

    ({ deployer, zeto } = await deployZeto("Zeto_NfAnon"));

    circuit = await loadCircuit("nf_anon");
    ({ provingKeyFile: provingKey } = loadProvingKeys("nf_anon"));
  });

  it("non-owner should not be able to mint", async function () {
    const utxo1 = newAssetUTXO(10, "http://ipfs.io/file-hash-1", Alice);
    await expect(doMint(zeto, Alice.signer, [utxo1])).to.be.rejectedWith(
      "OwnableUnauthorizedAccount",
    );
  });

  it("mint to Alice and transfer UTXOs honestly to Bob should succeed", async function () {
    const tokenId = 1001;
    const uri = "http://ipfs.io/file-hash-1";
    utxo1 = newAssetUTXO(tokenId, uri, Alice);
    await doMint(zeto, deployer, [utxo1]);

    // propose the output UTXOs
    const _utxo3 = newAssetUTXO(tokenId, uri, Bob);

    // transfer my own UTXOs to the Bob honestly should succeed
    await doTransfer(Alice, utxo1, _utxo3, Bob);

    // simulate Bob constructnig the UTXO from off-chain secure message channels with Alice
    utxo2 = newAssetUTXO(_utxo3.tokenId!, _utxo3.uri!, Bob, _utxo3.salt);
  });

  it("Bob transfers UTXOs, previously received from Alice, honestly to Charlie should succeed", async function () {
    // propose the output UTXOs
    utxo3 = newAssetUTXO(utxo2.tokenId!, utxo2.uri!, Charlie);

    // Bob should be able to spend the UTXO that was reconstructed from the previous transaction
    await doTransfer(Bob, utxo2, utxo3, Charlie);
  });

  describe("failure cases", function () {
    // the following failure cases rely on the hardhat network
    // to return the details of the errors. This is not possible
    // on non-hardhat networks
    if (network.name !== "hardhat") {
      return;
    }

    it("mint existing unspent UTXOs should fail", async function () {
      await expect(doMint(zeto, deployer, [utxo3])).rejectedWith(
        "UTXOAlreadyOwned",
      );
    });

    it("mint existing spent UTXOs should fail", async function () {
      await expect(doMint(zeto, deployer, [utxo1])).rejectedWith(
        "UTXOAlreadySpent",
      );
    });

    it("transfer non-existing UTXOs should fail", async function () {
      const nonExisting1 = newAssetUTXO(
        1002,
        "http://ipfs.io/file-hash-2",
        Alice,
      );
      const nonExisting2 = newAssetUTXO(
        1002,
        "http://ipfs.io/file-hash-2",
        Bob,
      );

      await expect(
        doTransfer(Alice, nonExisting1, nonExisting2, Bob),
      ).rejectedWith("UTXONotMinted");
    });

    it("transfer spent UTXOs should fail (double spend protection)", async function () {
      // create outputs
      const _utxo4 = newAssetUTXO(utxo1.tokenId!, utxo1.uri!, Bob);
      await expect(doTransfer(Alice, utxo1, _utxo4, Bob)).rejectedWith(
        "UTXOAlreadySpent",
      );
    });
  });

  describe("ILockableCapability tests", function () {
    // ABI fragments for the ZetoLockableCapability *Args payloads.
    // Mirrors the layout used in zeto_anon.ts so that the cross-token
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

    // mintAndLock mints a fresh UTXO under `owner`, then runs createLock
    // to convert it into a single locked UTXO of identical tokenId/uri.
    // Returns everything a downstream test needs to drive update /
    // delegate / spend / cancel without re-deriving any of it.
    async function mintAndLock(
      owner: User,
      tokenId: number,
      uri: string,
      spendCommitment: string = ethers.ZeroHash,
      cancelCommitment: string = ethers.ZeroHash,
    ): Promise<{
      lockId: string;
      sourceUtxo: UTXO;
      lockedUtxo: UTXO;
      createArgs: string;
    }> {
      const sourceUtxo = newAssetUTXO(tokenId, uri, owner);
      await doMint(zeto, deployer, [sourceUtxo]);

      const lockedUtxo = newAssetUTXO(tokenId, uri, owner);
      const { encodedProof } = await prepareProof(
        circuit,
        provingKey,
        owner,
        sourceUtxo,
        lockedUtxo,
        owner,
      );

      const createArgs = encodeCreateArgs({
        txId: randomBytes32(),
        inputs: [sourceUtxo.hash],
        outputs: [],
        lockedOutputs: [lockedUtxo.hash],
        proof: encodeToBytes(encodedProof),
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

    // dummySpendArgs returns a syntactically valid spend payload that
    // does NOT need to verify a real ZK proof. Tests for authorization
    // checks that short-circuit before the proof is touched can use this
    // to avoid the cost of generating a real proof.
    function dummySpendArgs(): string {
      return encodeSpendArgs({
        txId: randomBytes32(),
        lockedOutputs: [],
        outputs: [],
        proof: "0x",
        data: "0x",
      });
    }

    describe("createLock -> updateLock -> delegateLock -> spendLock flow", function () {
      const tokenId = 2001;
      const uri = "http://ipfs.io/lock-flow-1";
      let bobSourceUtxo: UTXO;
      let lockedUtxo: UTXO;
      let lockId: string;
      let outUtxo: UTXO;
      let unlockHash: string;

      it("createLock() with deterministic lockId computed from txId", async function () {
        bobSourceUtxo = newAssetUTXO(tokenId, uri, Bob);
        await doMint(zeto, deployer, [bobSourceUtxo]);

        // Locked content is a fresh UTXO of identical tokenId/uri held
        // under Bob. The ZK proof on the create path is the standard
        // 1-in/1-out NF transfer relationship — the locked output is
        // treated identically to a regular output for circuit purposes.
        lockedUtxo = newAssetUTXO(tokenId, uri, Bob);
        const { encodedProof } = await prepareProof(
          circuit,
          provingKey,
          Bob,
          bobSourceUtxo,
          lockedUtxo,
          Bob,
        );

        const createArgs = encodeCreateArgs({
          txId: randomBytes32(),
          inputs: [bobSourceUtxo.hash],
          outputs: [],
          lockedOutputs: [lockedUtxo.hash],
          proof: encodeToBytes(encodedProof),
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
          .find((p: any) => p && p.name === "LockCreated");
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

      it("locked() returns (true, spender) for locked UTXOs and (false, 0) otherwise", async function () {
        // Just-created lock: spender == owner == Bob.
        expect(await zeto.locked(lockedUtxo.hash)).to.deep.equal([
          true,
          Bob.ethAddress,
        ]);
        // Source UTXO is now spent (consumed by createLock), so it is
        // not locked.
        expect((await zeto.locked(bobSourceUtxo.hash))[0]).to.be.false;
      });

      it("updateLock() commits the spend hash while owner == spender", async function () {
        outUtxo = newAssetUTXO(tokenId, uri, Charlie);

        // For NF, the spend payload is a single unlocked output —
        // there's no second-output split to consider.
        unlockHash = calculateSpendHash([lockedUtxo], [], [outUtxo], "0x");

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
        // Per-UTXO delegate projection in ZetoLockable must reflect the
        // new spender.
        expect(await zeto.locked(lockedUtxo.hash)).to.deep.equal([
          true,
          Alice.ethAddress,
        ]);
      });

      it("the new spender can spendLock() with the matching payload", async function () {
        const { encodedProof } = await prepareProof(
          circuit,
          provingKey,
          Bob,
          lockedUtxo,
          outUtxo,
          Charlie,
        );

        const spendArgs = encodeSpendArgs({
          txId: randomBytes32(),
          lockedOutputs: [],
          outputs: [outUtxo.hash],
          proof: encodeToBytes(encodedProof),
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
          .filter((p: any) => p !== null) as ReadonlyArray<{
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

        // Output is now an ordinary unlocked UTXO.
        expect(await zeto.spent(outUtxo.hash)).to.equal(1n); // UNSPENT

        // Per-UTXO delegate projection is cleared post-consume.
        expect(await zeto.locked(lockedUtxo.hash)).to.deep.equal([
          false,
          ZeroAddress,
        ]);
      });
    });

    describe("createLock -> cancelLock flow", function () {
      const tokenId = 2002;
      const uri = "http://ipfs.io/lock-flow-2";
      let bobSourceUtxo: UTXO;
      let lockedUtxo: UTXO;
      let lockId: string;
      let cancelHash: string;
      let outUtxo: UTXO;

      it("Bob createLock() with a non-zero cancelCommitment", async function () {
        bobSourceUtxo = newAssetUTXO(tokenId, uri, Bob);
        await doMint(zeto, deployer, [bobSourceUtxo]);

        lockedUtxo = newAssetUTXO(tokenId, uri, Bob);
        const { encodedProof } = await prepareProof(
          circuit,
          provingKey,
          Bob,
          bobSourceUtxo,
          lockedUtxo,
          Bob,
        );

        outUtxo = newAssetUTXO(tokenId, uri, Bob);
        cancelHash = calculateCancelHash([lockedUtxo], [], [outUtxo], "0x");

        const createArgs = encodeCreateArgs({
          txId: randomBytes32(),
          inputs: [bobSourceUtxo.hash],
          outputs: [],
          lockedOutputs: [lockedUtxo.hash],
          proof: encodeToBytes(encodedProof),
        });
        lockId = await zeto.connect(Bob.signer).computeLockId(createArgs);
        await (
          await zeto
            .connect(Bob.signer)
            .createLock(createArgs, ethers.ZeroHash, cancelHash, "0x")
        ).wait();
      });

      it("the owner can cancelLock() to reverse the lock without delegation", async function () {
        const { encodedProof } = await prepareProof(
          circuit,
          provingKey,
          Bob,
          lockedUtxo,
          outUtxo,
          Bob,
        );

        const cancelArgs = encodeSpendArgs({
          txId: randomBytes32(),
          lockedOutputs: [],
          outputs: [outUtxo.hash],
          proof: encodeToBytes(encodedProof),
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
          .filter((p: any) => p !== null) as ReadonlyArray<{
            name: string;
            args: any;
          }>;
        const cancelled = parsed.find((p) => p.name === "LockCancelled");
        const zetoCancelled = parsed.find((p) => p.name === "ZetoLockCancelled");
        expect(cancelled, "LockCancelled event not emitted").to.not.be
          .undefined;
        expect(zetoCancelled, "ZetoLockCancelled event not emitted").to.not.be
          .undefined;

        expect(await zeto.isLockActive(lockId)).to.equal(false);
        expect(await zeto.spent(outUtxo.hash)).to.equal(1n); // UNSPENT
      });
    });

    describe("spendLock with a payload that does not match the spend commitment fails", function () {
      const tokenId = 2003;
      const uri = "http://ipfs.io/lock-flow-3";
      let lockedUtxo: UTXO;
      let lockId: string;
      let expectedHash: string;

      before(async function () {
        // Mint, lock, then commit to a specific spend payload.
        const bobSourceUtxo = newAssetUTXO(tokenId, uri, Bob);
        await doMint(zeto, deployer, [bobSourceUtxo]);

        lockedUtxo = newAssetUTXO(tokenId, uri, Bob);
        const { encodedProof } = await prepareProof(
          circuit,
          provingKey,
          Bob,
          bobSourceUtxo,
          lockedUtxo,
          Bob,
        );

        const createArgs = encodeCreateArgs({
          txId: randomBytes32(),
          inputs: [bobSourceUtxo.hash],
          outputs: [],
          lockedOutputs: [lockedUtxo.hash],
          proof: encodeToBytes(encodedProof),
        });
        lockId = await zeto.connect(Bob.signer).computeLockId(createArgs);
        await (
          await zeto
            .connect(Bob.signer)
            .createLock(createArgs, ethers.ZeroHash, ethers.ZeroHash, "0x")
        ).wait();

        const expectedOut = newAssetUTXO(tokenId, uri, Charlie);
        expectedHash = calculateSpendHash(
          [lockedUtxo],
          [],
          [expectedOut],
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
        const wrongOut = newAssetUTXO(tokenId, uri, Alice);

        const { encodedProof } = await prepareProof(
          circuit,
          provingKey,
          Bob,
          lockedUtxo,
          wrongOut,
          Alice,
        );

        const spendArgs = encodeSpendArgs({
          txId: randomBytes32(),
          lockedOutputs: [],
          outputs: [wrongOut.hash],
          proof: encodeToBytes(encodedProof),
          data: "0x",
        });

        const calculatedHash = calculateSpendHash(
          [lockedUtxo],
          [],
          [wrongOut],
          "0x",
        );

        await expect(
          zeto.connect(Bob.signer).spendLock(lockId, spendArgs, "0x"),
        )
          .to.be.revertedWithCustomError(zeto, "InvalidUnlockHash")
          .withArgs(expectedHash, calculatedHash);
      });
    });

    describe("locked inputs cannot be re-spent via plain transfer", function () {
      // A locked UTXO must not be consumable by the public transfer()
      // entry point — only spendLock / cancelLock can move it. The
      // storage layer enforces this with `AlreadyLocked`.
      if (network.name !== "hardhat") {
        return;
      }

      it("transfer() of a locked UTXO reverts with AlreadyLocked", async function () {
        const tokenId = 2010;
        const uri = "http://ipfs.io/locked-no-transfer";
        const { lockedUtxo } = await mintAndLock(Bob, tokenId, uri);

        // Output must preserve tokenId/uri to satisfy the NF circuit's
        // mass-conservation invariant; otherwise the proof would not
        // even be computable and we'd never reach the storage layer's
        // AlreadyLocked check.
        const otherUtxo = newAssetUTXO(tokenId, uri, Bob);
        await expect(doTransfer(Bob, lockedUtxo, otherUtxo, Bob)).rejectedWith(
          "AlreadyLocked",
        );
      });
    });

    describe("negative cases for the lock lifecycle", function () {
      // These tests rely on hardhat-style revert decoding.
      if (network.name !== "hardhat") {
        return;
      }

      it("createLock() with a duplicate txId from the same caller reverts with DuplicateLock", async function () {
        const { lockId, createArgs } = await mintAndLock(
          Bob,
          3001,
          "http://ipfs.io/dup-lock",
        );

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
        const { lockId } = await mintAndLock(
          Bob,
          3002,
          "http://ipfs.io/non-owner-update",
        );

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

      it("updateLock() prefers LockUnauthorized over LockImmutable when both apply", async function () {
        // Lock is delegated (so spender != owner -> immutable) AND the
        // caller is neither owner nor spender. The contract MUST report
        // LockUnauthorized, not leak the immutability state to the
        // unauthorized caller.
        const { lockId } = await mintAndLock(
          Bob,
          3003,
          "http://ipfs.io/auth-over-immut",
        );
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
          .withArgs(lockId, Bob.ethAddress, Charlie.ethAddress);
      });

      it("updateLock() after delegateLock() reverts with LockImmutable", async function () {
        const { lockId } = await mintAndLock(
          Bob,
          3004,
          "http://ipfs.io/immut-after-delegate",
        );

        // Bob delegates spending authority to Alice; spender (Alice)
        // now differs from owner (Bob).
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
        const { lockId } = await mintAndLock(
          Bob,
          3005,
          "http://ipfs.io/non-spender-delegate",
        );

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
        const { lockId } = await mintAndLock(
          Bob,
          3006,
          "http://ipfs.io/non-spender-spend",
        );

        // Garbage proof — the onlySpender modifier MUST short-circuit
        // before any proof verification is attempted.
        await expect(
          zeto.connect(Alice.signer).spendLock(lockId, dummySpendArgs(), "0x"),
        )
          .to.be.revertedWithCustomError(zeto, "LockUnauthorized")
          .withArgs(lockId, Bob.ethAddress, Alice.ethAddress);
      });

      it("cancelLock() by a non-spender reverts with LockUnauthorized", async function () {
        const { lockId } = await mintAndLock(
          Bob,
          3007,
          "http://ipfs.io/non-spender-cancel",
        );

        await expect(
          zeto.connect(Alice.signer).cancelLock(lockId, dummySpendArgs(), "0x"),
        )
          .to.be.revertedWithCustomError(zeto, "LockUnauthorized")
          .withArgs(lockId, Bob.ethAddress, Alice.ethAddress);
      });

      it("after a successful spendLock(), getLock() reverts with LockNotActive", async function () {
        const tokenId = 3008;
        const uri = "http://ipfs.io/post-spend-getlock";
        const { lockId, lockedUtxo } = await mintAndLock(Bob, tokenId, uri);

        const outUtxo = newAssetUTXO(tokenId, uri, Bob);
        const { encodedProof } = await prepareProof(
          circuit,
          provingKey,
          Bob,
          lockedUtxo,
          outUtxo,
          Bob,
        );
        const spendArgs = encodeSpendArgs({
          txId: randomBytes32(),
          lockedOutputs: [],
          outputs: [outUtxo.hash],
          proof: encodeToBytes(encodedProof),
          data: "0x",
        });
        await (
          await zeto.connect(Bob.signer).spendLock(lockId, spendArgs, "0x")
        ).wait();

        await expect(zeto.getLock(lockId))
          .to.be.revertedWithCustomError(zeto, "LockNotActive")
          .withArgs(lockId);
        expect(await zeto.isLockActive(lockId)).to.equal(false);
      });

      it("InvalidNonFungibleArity fires when createLock supplies more than one input", async function () {
        const tokenId = 3009;
        const uri = "http://ipfs.io/arity-create";

        const u1 = newAssetUTXO(tokenId, uri, Bob);
        const u2 = newAssetUTXO(tokenId + 1, uri + "2", Bob);
        await doMint(zeto, deployer, [u1, u2]);

        const lockedUtxo = newAssetUTXO(tokenId, uri, Bob);
        // Borrow a real proof for the (u1 -> lockedUtxo) transition;
        // the InvalidNonFungibleArity check fires before the verifier is
        // touched, so a real proof is not strictly required, but the
        // payload must still be well-formed bytes.
        const { encodedProof } = await prepareProof(
          circuit,
          provingKey,
          Bob,
          u1,
          lockedUtxo,
          Bob,
        );

        const createArgs = encodeCreateArgs({
          txId: randomBytes32(),
          // Two inputs is invalid for the NF lock circuit: a single
          // token cannot be split.
          inputs: [u1.hash, u2.hash],
          outputs: [],
          lockedOutputs: [lockedUtxo.hash],
          proof: encodeToBytes(encodedProof),
        });

        await expect(
          zeto
            .connect(Bob.signer)
            .createLock(createArgs, ethers.ZeroHash, ethers.ZeroHash, "0x"),
        )
          .to.be.revertedWithCustomError(zeto, "InvalidNonFungibleArity")
          .withArgs(2, 0, 1);
      });
    });
  });

  async function doTransfer(signer: User, input: UTXO, output: UTXO, to: User) {
    let inputCommitment: BigNumberish;
    let outputCommitment: BigNumberish;
    let outputOwnerAddress: AddressLike;
    let encodedProof: any;
    const result = await prepareProof(
      circuit,
      provingKey,
      signer,
      input,
      output,
      to,
    );
    inputCommitment = result.inputCommitment;
    outputCommitment = result.outputCommitment;
    outputOwnerAddress = to.ethAddress as AddressLike;
    encodedProof = result.encodedProof;

    await sendTx(signer, inputCommitment, outputCommitment, encodedProof);
  }

  async function sendTx(
    signer: User,
    inputCommitment: BigNumberish,
    outputCommitment: BigNumberish,
    encodedProof: any,
  ) {
    const proof = encodeToBytes(encodedProof);
    const tx = await zeto
      .connect(signer.signer)
      .transfer(inputCommitment, outputCommitment, proof, "0x");
    const results = await tx.wait();
    logger.debug(`Method transfer() complete. Gas used: ${results?.gasUsed}`);

    expect(await zeto.spent(inputCommitment)).to.equal(2n); // UTXOStatus.SPENT
    expect(await zeto.spent(outputCommitment)).to.equal(1n); // UTXOStatus.UNSPENT
  }
});

async function prepareProof(
  circuit: any,
  provingKey: any,
  signer: User,
  input: UTXO,
  output: UTXO,
  to: User,
) {
  const tokenId = input.tokenId;
  const inputCommitment: BigNumberish = input.hash as BigNumberish;
  const inputSalt = input.salt;
  const outputCommitment: BigNumberish = output.hash as BigNumberish;
  const outputOwnerPublicKey: [BigNumberish, BigNumberish] =
    to.babyJubPublicKey as [BigNumberish, BigNumberish];
  const otherInputs = stringifyBigInts({
    inputOwnerPrivateKey: formatPrivKeyForBabyJub(signer.babyJubPrivateKey),
  });

  const startWitnessCalculation = Date.now();
  const witness = await circuit.calculateWTNSBin(
    {
      tokenIds: [tokenId],
      tokenUris: [tokenUriHash(input.uri)],
      inputCommitments: [inputCommitment],
      inputSalts: [inputSalt],
      outputCommitments: [outputCommitment],
      outputSalts: [output.salt],
      outputOwnerPublicKeys: [outputOwnerPublicKey],
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
  return {
    inputCommitment,
    outputCommitment,
    encodedProof,
  };
}

function encodeToBytes(proof: any) {
  return new AbiCoder().encode(
    ["tuple(uint256[2] pA, uint256[2][2] pB, uint256[2] pC)"],
    [proof],
  );
}

module.exports = {
  prepareProof,
};
