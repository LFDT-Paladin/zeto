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
  ContractTransactionReceipt,
  Signer,
  BigNumberish,
  AbiCoder,
  ZeroAddress,
} from "ethers";
import { expect } from "chai";
import { loadCircuit, Poseidon, encodeProof, tokenUriHash } from "zeto-js";
import { groth16 } from "snarkjs";
import { formatPrivKeyForBabyJub, stringifyBigInts } from "maci-crypto";
import { Merkletree, InMemoryDB, str2Bytes } from "@iden3/js-merkletree";
import {
  UTXO,
  User,
  newUser,
  newAssetUTXO,
  newAssetNullifier,
  doMint,
  parseUTXOEvents,
  logger,
} from "./lib/utils";
import {
  loadProvingKeys,
  calculateSpendHash,
  calculateCancelHash,
} from "./utils";
import { deployZeto } from "./lib/deploy";
describe("Zeto based non-fungible token with anonymity using nullifiers without encryption", function () {
  let deployer: Signer;
  let Alice: User;
  let Bob: User;
  let Charlie: User;
  let zeto: any;
  let utxo1: UTXO;
  let utxo2: UTXO;
  let circuit: any, provingKey: any;
  // The locked-input transition reuses the simple `nf_anon` circuit
  // (1-in/1-out, no nullifier, no merkle proof). Mirrors how
  // {Zeto_AnonNullifier} reuses `anon` as its lock verifier — the
  // contract storage layer already vouches that the input is in the
  // locked-UTXO ledger, so the proof does not need to re-prove
  // inclusion in any tree.
  let circuitLocked: any, provingKeyLocked: any;
  let smtAlice: Merkletree;
  let smtBob: Merkletree;

  before(async function () {
    if (network.name !== "hardhat") {
      this.timeout(120000);
    }
    let [d, a, b, c] = await ethers.getSigners();
    deployer = d;
    Alice = await newUser(a);
    Bob = await newUser(b);
    Charlie = await newUser(c);

    ({ deployer, zeto } = await deployZeto("Zeto_NfAnonNullifier"));

    circuit = await loadCircuit("nf_anon_nullifier_transfer");
    ({ provingKeyFile: provingKey } = loadProvingKeys(
      "nf_anon_nullifier_transfer",
    ));
    circuitLocked = await loadCircuit("nf_anon");
    ({ provingKeyFile: provingKeyLocked } = loadProvingKeys("nf_anon"));

    const storage1 = new InMemoryDB(str2Bytes(""));
    smtAlice = new Merkletree(storage1, true, 64);

    const storage2 = new InMemoryDB(str2Bytes(""));
    smtBob = new Merkletree(storage2, true, 64);
  });

  it("onchain SMT root should be equal to the offchain SMT root", async function () {
    const root = await smtAlice.root();
    const onchainRoot = await zeto.getRoot();
    expect(onchainRoot).to.equal(0n);
    expect(root.string()).to.equal(onchainRoot.toString());
  });

  it("mint to Alice and transfer UTXOs honestly to Bob should succeed", async function () {
    const tokenId = 1001;
    const uri = "http://ipfs.io/file-hash-1";
    utxo1 = newAssetUTXO(tokenId, uri, Alice);
    const result1 = await doMint(zeto, deployer, [utxo1]);

    const mintEvents = parseUTXOEvents(zeto, result1);
    const [_utxo1] = mintEvents[0].outputs;
    await smtAlice.add(_utxo1, _utxo1);
    let root = await smtAlice.root();
    let onchainRoot = await zeto.getRoot();
    expect(root.string()).to.equal(onchainRoot.toString());
    await smtBob.add(_utxo1, _utxo1);

    const _utxo2 = newAssetUTXO(tokenId, uri, Bob);
    const nullifier1 = newAssetNullifier(utxo1, Alice);
    const proof1 = await smtAlice.generateCircomVerifierProof(utxo1.hash, root);
    const merkleProof = proof1.siblings.map((s) => s.bigInt());

    const result2 = await doTransfer(
      Alice,
      utxo1,
      nullifier1,
      _utxo2,
      root.bigInt(),
      merkleProof,
      Bob,
    );

    await smtAlice.add(_utxo2.hash, _utxo2.hash);
    root = await smtAlice.root();
    onchainRoot = await zeto.getRoot();
    expect(root.string()).to.equal(onchainRoot.toString());

    const signerAddress = await Alice.signer.getAddress();
    const events = parseUTXOEvents(zeto, result2.txResult!);
    expect(events[0].submitter).to.equal(signerAddress);
    expect(events[0].inputs).to.deep.equal([nullifier1.hash]);
    expect(events[0].outputs).to.deep.equal([_utxo2.hash]);
    await smtBob.add(events[0].outputs[0], events[0].outputs[0]);

    // Bob reconstructs the UTXO from the off-chain channel.
    const receivedTokenId = _utxo2.tokenId!;
    const receivedUri = _utxo2.uri!;
    const receivedSalt = _utxo2.salt;
    const incomingUTXOs: any = events[0].outputs;
    const hash = Poseidon.poseidon5([
      BigInt(receivedTokenId),
      tokenUriHash(receivedUri),
      receivedSalt,
      Bob.babyJubPublicKey[0],
      Bob.babyJubPublicKey[1],
    ]);
    expect(incomingUTXOs[0]).to.equal(hash);

    utxo2 = newAssetUTXO(receivedTokenId, receivedUri, Bob, receivedSalt);
  }).timeout(600000);

  it("Bob transfers UTXOs, previously received from Alice, honestly to Charlie should succeed", async function () {
    const nullifier1 = newAssetNullifier(utxo2, Bob);
    const root = await smtBob.root();
    const proof1 = await smtBob.generateCircomVerifierProof(utxo2.hash, root);
    const merkleProof = proof1.siblings.map((s) => s.bigInt());

    const _utxo1 = newAssetUTXO(utxo2.tokenId!, utxo2.uri!, Charlie);

    const result = await doTransfer(
      Bob,
      utxo2,
      nullifier1,
      _utxo1,
      root.bigInt(),
      merkleProof,
      Charlie,
    );

    await smtBob.add(_utxo1.hash, _utxo1.hash);

    const events = parseUTXOEvents(zeto, result.txResult!);
    await smtAlice.add(events[0].outputs[0], events[0].outputs[0]);
  }).timeout(600000);

  describe("failure cases", function () {
    if (network.name !== "hardhat") {
      return;
    }

    it("mint existing unspent UTXOs should fail", async function () {
      await expect(doMint(zeto, deployer, [utxo2])).rejectedWith(
        "UTXOAlreadyOwned",
      );
    });

    it("mint existing spent UTXOs should fail", async function () {
      await expect(doMint(zeto, deployer, [utxo1])).rejectedWith(
        "UTXOAlreadyOwned",
      );
    });

    it("transfer spent UTXOs should fail (double spend protection)", async function () {
      const _utxo1 = newAssetUTXO(utxo1.tokenId!, utxo1.uri!, Charlie);
      const nullifier1 = newAssetNullifier(utxo1, Alice);

      let root = await smtAlice.root();
      const proof1 = await smtAlice.generateCircomVerifierProof(
        utxo1.hash,
        root,
      );
      const merkleProof = proof1.siblings.map((s) => s.bigInt());

      await expect(
        doTransfer(
          Alice,
          utxo1,
          nullifier1,
          _utxo1,
          root.bigInt(),
          merkleProof,
          Charlie,
        ),
      ).rejectedWith("UTXOAlreadySpent");
    }).timeout(600000);

    it("transfer non-existing UTXOs should fail", async function () {
      const nonExisting1 = newAssetUTXO(
        9001,
        "http://ipfs.io/non-existing",
        Alice,
      );

      // add to our local SMT (but they don't exist on the chain)
      await smtAlice.add(nonExisting1.hash, nonExisting1.hash);

      const nullifier1 = newAssetNullifier(nonExisting1, Alice);
      let root = await smtAlice.root();
      const proof1 = await smtAlice.generateCircomVerifierProof(
        nonExisting1.hash,
        root,
      );
      const merkleProof = proof1.siblings.map((s) => s.bigInt());

      const _utxo1 = newAssetUTXO(
        nonExisting1.tokenId!,
        nonExisting1.uri!,
        Charlie,
      );

      await expect(
        doTransfer(
          Alice,
          nonExisting1,
          nullifier1,
          _utxo1,
          root.bigInt(),
          merkleProof,
          Charlie,
        ),
      ).rejectedWith("UTXORootNotFound");
    }).timeout(600000);
  });

  describe("ILockableCapability tests", function () {
    // ABI fragments mirror the layout used in zeto_anon_nullifier.ts;
    // these payloads are uniform across all Zeto tokens that implement
    // {ILockableCapability}.
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

    // mintAndLock mints a fresh UTXO under `owner`, runs createLock to
    // convert it into a single locked UTXO of identical tokenId/uri,
    // and returns everything a downstream test needs to drive
    // update/delegate/spend/cancel without re-deriving any of it.
    // Also mirrors the post-mint state into both SMTs so subsequent
    // tests in the file that depend on tree consistency can keep
    // ticking.
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
      await smtAlice.add(sourceUtxo.hash, sourceUtxo.hash);
      await smtBob.add(sourceUtxo.hash, sourceUtxo.hash);

      const nullifier = newAssetNullifier(sourceUtxo, owner);
      const root = await smtBob.root();
      const proof = await smtBob.generateCircomVerifierProof(
        sourceUtxo.hash,
        root,
      );
      const merkleProof = proof.siblings.map((s) => s.bigInt());

      const lockedUtxo = newAssetUTXO(tokenId, uri, owner);
      const { encodedProof } = await prepareProof(
        owner,
        sourceUtxo,
        nullifier,
        lockedUtxo,
        root.bigInt(),
        merkleProof,
        owner,
      );

      const createArgs = encodeCreateArgs({
        txId: randomBytes32(),
        inputs: [nullifier.hash],
        outputs: [],
        lockedOutputs: [lockedUtxo.hash],
        proof: encodeUnlockedProof(root.bigInt(), encodedProof),
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
    // checks that short-circuit before the proof is touched can use
    // this to avoid the cost of generating a real proof.
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
        await smtAlice.add(bobSourceUtxo.hash, bobSourceUtxo.hash);
        await smtBob.add(bobSourceUtxo.hash, bobSourceUtxo.hash);

        const nullifier = newAssetNullifier(bobSourceUtxo, Bob);
        const root = await smtBob.root();
        const p = await smtBob.generateCircomVerifierProof(
          bobSourceUtxo.hash,
          root,
        );
        const merkleProof = p.siblings.map((s) => s.bigInt());

        lockedUtxo = newAssetUTXO(tokenId, uri, Bob);
        const { encodedProof } = await prepareProof(
          Bob,
          bobSourceUtxo,
          nullifier,
          lockedUtxo,
          root.bigInt(),
          merkleProof,
          Bob,
        );

        const createArgs = encodeCreateArgs({
          txId: randomBytes32(),
          inputs: [nullifier.hash],
          outputs: [],
          lockedOutputs: [lockedUtxo.hash],
          proof: encodeUnlockedProof(root.bigInt(), encodedProof),
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
      }).timeout(600000);

      it("isLockActive() and getLock() reflect the newly created lock", async function () {
        expect(await zeto.isLockActive(lockId)).to.equal(true);
        const info = await zeto.getLock(lockId);
        expect(info.owner).to.equal(Bob.ethAddress);
        expect(info.spender).to.equal(Bob.ethAddress);
        expect(info.spendCommitment).to.equal(ethers.ZeroHash);
        expect(info.cancelCommitment).to.equal(ethers.ZeroHash);
      });

      it("locked() returns (true, spender) for locked UTXOs and (false, 0) otherwise", async function () {
        expect(await zeto.locked(lockedUtxo.hash)).to.deep.equal([
          true,
          Bob.ethAddress,
        ]);
        // The source UTXO is consumed by createLock (its nullifier is
        // recorded in `_nullifiers`) but the SMT entry remains -- the
        // tree is append-only. From the ledger's point of view, the
        // source hash is not locked.
        expect((await zeto.locked(bobSourceUtxo.hash))[0]).to.be.false;
      });

      it("updateLock() commits the spend hash while owner == spender", async function () {
        outUtxo = newAssetUTXO(tokenId, uri, Charlie);
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
        expect(await zeto.locked(lockedUtxo.hash)).to.deep.equal([
          true,
          Alice.ethAddress,
        ]);
      });

      it("the new spender can spendLock() with the matching payload", async function () {
        // Locked-input transition: simple `nf_anon` proof against the
        // locked UTXO hash.
        const { encodedProof } = await prepareLockedProof(
          Bob,
          lockedUtxo,
          outUtxo,
          Charlie,
        );

        const spendArgs = encodeSpendArgs({
          txId: randomBytes32(),
          lockedOutputs: [],
          outputs: [outUtxo.hash],
          proof: encodeLockedProof(encodedProof),
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

        // Newly-unlocked output is added to the unlocked SMT by the
        // contract; mirror it off-chain to keep the trees in sync.
        await smtAlice.add(outUtxo.hash, outUtxo.hash);
        await smtBob.add(outUtxo.hash, outUtxo.hash);

        // Lock is consumed.
        expect(await zeto.isLockActive(lockId)).to.equal(false);
        expect(await zeto.locked(lockedUtxo.hash)).to.deep.equal([
          false,
          ZeroAddress,
        ]);
      }).timeout(600000);

      it("onchain SMT root for the unlocked UTXOs equals the offchain SMT root", async function () {
        const bobRoot = await smtBob.root();
        const aliceRoot = await smtAlice.root();
        const onchainRoot = await zeto.getRoot();
        // smtAlice has been polluted by the failure-case test that
        // appends a non-existing leaf; we don't compare it here. smtBob
        // however should mirror the on-chain unlocked SMT.
        expect(bobRoot.string()).to.equal(onchainRoot.toString());
        expect(aliceRoot.string()).to.not.equal(onchainRoot.toString());
      });
    });

    describe("createLock -> cancelLock flow", function () {
      const tokenId = 2002;
      const uri = "http://ipfs.io/lock-flow-2";
      let lockedUtxo: UTXO;
      let lockId: string;
      let outUtxo: UTXO;
      let cancelHash: string;

      it("Bob createLock() with a non-zero cancelCommitment", async function () {
        const sourceUtxo = newAssetUTXO(tokenId, uri, Bob);
        await doMint(zeto, deployer, [sourceUtxo]);
        await smtAlice.add(sourceUtxo.hash, sourceUtxo.hash);
        await smtBob.add(sourceUtxo.hash, sourceUtxo.hash);

        const nullifier = newAssetNullifier(sourceUtxo, Bob);
        const root = await smtBob.root();
        const p = await smtBob.generateCircomVerifierProof(
          sourceUtxo.hash,
          root,
        );
        const merkleProof = p.siblings.map((s) => s.bigInt());

        lockedUtxo = newAssetUTXO(tokenId, uri, Bob);
        const { encodedProof } = await prepareProof(
          Bob,
          sourceUtxo,
          nullifier,
          lockedUtxo,
          root.bigInt(),
          merkleProof,
          Bob,
        );

        outUtxo = newAssetUTXO(tokenId, uri, Bob);
        cancelHash = calculateCancelHash([lockedUtxo], [], [outUtxo], "0x");

        const createArgs = encodeCreateArgs({
          txId: randomBytes32(),
          inputs: [nullifier.hash],
          outputs: [],
          lockedOutputs: [lockedUtxo.hash],
          proof: encodeUnlockedProof(root.bigInt(), encodedProof),
        });
        lockId = await zeto.connect(Bob.signer).computeLockId(createArgs);
        await (
          await zeto
            .connect(Bob.signer)
            .createLock(createArgs, ethers.ZeroHash, cancelHash, "0x")
        ).wait();
      }).timeout(600000);

      it("the owner can cancelLock() to reverse the lock without delegation", async function () {
        const { encodedProof } = await prepareLockedProof(
          Bob,
          lockedUtxo,
          outUtxo,
          Bob,
        );

        const cancelArgs = encodeSpendArgs({
          txId: randomBytes32(),
          lockedOutputs: [],
          outputs: [outUtxo.hash],
          proof: encodeLockedProof(encodedProof),
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

        await smtAlice.add(outUtxo.hash, outUtxo.hash);
        await smtBob.add(outUtxo.hash, outUtxo.hash);

        expect(await zeto.isLockActive(lockId)).to.equal(false);
      }).timeout(600000);
    });

    describe("spendLock with a payload that does not match the spend commitment fails", function () {
      const tokenId = 2003;
      const uri = "http://ipfs.io/lock-flow-3";
      let lockedUtxo: UTXO;
      let lockId: string;
      let expectedHash: string;

      before(async function () {
        const sourceUtxo = newAssetUTXO(tokenId, uri, Bob);
        await doMint(zeto, deployer, [sourceUtxo]);
        await smtAlice.add(sourceUtxo.hash, sourceUtxo.hash);
        await smtBob.add(sourceUtxo.hash, sourceUtxo.hash);

        const nullifier = newAssetNullifier(sourceUtxo, Bob);
        const root = await smtBob.root();
        const p = await smtBob.generateCircomVerifierProof(
          sourceUtxo.hash,
          root,
        );
        const merkleProof = p.siblings.map((s) => s.bigInt());

        lockedUtxo = newAssetUTXO(tokenId, uri, Bob);
        const { encodedProof } = await prepareProof(
          Bob,
          sourceUtxo,
          nullifier,
          lockedUtxo,
          root.bigInt(),
          merkleProof,
          Bob,
        );

        const createArgs = encodeCreateArgs({
          txId: randomBytes32(),
          inputs: [nullifier.hash],
          outputs: [],
          lockedOutputs: [lockedUtxo.hash],
          proof: encodeUnlockedProof(root.bigInt(), encodedProof),
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
        const { encodedProof } = await prepareLockedProof(
          Bob,
          lockedUtxo,
          wrongOut,
          Alice,
        );

        const spendArgs = encodeSpendArgs({
          txId: randomBytes32(),
          lockedOutputs: [],
          outputs: [wrongOut.hash],
          proof: encodeLockedProof(encodedProof),
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
      }).timeout(600000);
    });

    describe("locked inputs cannot be re-spent via plain transfer", function () {
      // The unlocked-input transfer path runs through
      // {NullifierStorage.validateInputs} with `inputsLocked=false`.
      // For nullifier-based tokens, that path doesn't read the locked
      // UTXO ledger directly (it only checks the `_nullifiers`
      // mapping), so the locked-protection comes via a different
      // mechanism: the off-chain attempt to construct a Merkle
      // inclusion proof for the locked UTXO will fail because the
      // locked output was never added to `_commitmentsTree`. Thus
      // building the witness against `getRoot()` will produce a proof
      // whose root the contract has never seen, surfacing as
      // {UTXORootNotFound}. This is the nullifier-flavour analogue of
      // the {AlreadyLocked} guard in the non-nullifier path.
      if (network.name !== "hardhat") {
        return;
      }

      it("transfer() of a locked UTXO reverts because the locked-UTXO root is not in the unlocked SMT", async function () {
        const tokenId = 2010;
        const uri = "http://ipfs.io/locked-no-transfer";
        const { lockedUtxo } = await mintAndLock(Bob, tokenId, uri);

        // Pretend off-chain we try to spend the locked UTXO via the
        // public transfer() path. We add the locked UTXO to a local
        // SMT (the contract never did) and then try to prove it.
        const localStorage = new InMemoryDB(str2Bytes(""));
        const localSmt = new Merkletree(localStorage, true, 64);
        await localSmt.add(lockedUtxo.hash, lockedUtxo.hash);
        const root = await localSmt.root();
        const p = await localSmt.generateCircomVerifierProof(
          lockedUtxo.hash,
          root,
        );
        const merkleProof = p.siblings.map((s) => s.bigInt());

        const nullifier = newAssetNullifier(lockedUtxo, Bob);
        const otherUtxo = newAssetUTXO(tokenId, uri, Bob);
        const result = await prepareProof(
          Bob,
          lockedUtxo,
          nullifier,
          otherUtxo,
          root.bigInt(),
          merkleProof,
          Bob,
        );

        await expect(
          zeto
            .connect(Bob.signer)
            .transfer(
              nullifier.hash,
              otherUtxo.hash,
              encodeUnlockedProof(root.bigInt(), result.encodedProof),
              "0x",
            ),
        ).rejectedWith("UTXORootNotFound");
      }).timeout(600000);
    });

    describe("negative cases for the lock lifecycle", function () {
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
      }).timeout(600000);

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
      }).timeout(600000);

      it("updateLock() after delegateLock() reverts with LockImmutable", async function () {
        const { lockId } = await mintAndLock(
          Bob,
          3003,
          "http://ipfs.io/immut-after-delegate",
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
      }).timeout(600000);

      it("delegateLock() by a non-spender reverts with LockUnauthorized", async function () {
        const { lockId } = await mintAndLock(
          Bob,
          3004,
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
      }).timeout(600000);

      it("spendLock() by a non-spender reverts with LockUnauthorized before touching the proof", async function () {
        const { lockId } = await mintAndLock(
          Bob,
          3005,
          "http://ipfs.io/non-spender-spend",
        );

        await expect(
          zeto.connect(Alice.signer).spendLock(lockId, dummySpendArgs(), "0x"),
        )
          .to.be.revertedWithCustomError(zeto, "LockUnauthorized")
          .withArgs(lockId, Bob.ethAddress, Alice.ethAddress);
      }).timeout(600000);

      it("cancelLock() by a non-spender reverts with LockUnauthorized", async function () {
        const { lockId } = await mintAndLock(
          Bob,
          3006,
          "http://ipfs.io/non-spender-cancel",
        );

        await expect(
          zeto.connect(Alice.signer).cancelLock(lockId, dummySpendArgs(), "0x"),
        )
          .to.be.revertedWithCustomError(zeto, "LockUnauthorized")
          .withArgs(lockId, Bob.ethAddress, Alice.ethAddress);
      }).timeout(600000);

      it("InvalidNonFungibleArity fires when createLock supplies more than one input", async function () {
        const tokenId1 = 3010;
        const tokenId2 = 3011;
        const uri = "http://ipfs.io/arity-create";

        const u1 = newAssetUTXO(tokenId1, uri, Bob);
        const u2 = newAssetUTXO(tokenId2, uri + "2", Bob);
        await doMint(zeto, deployer, [u1, u2]);
        await smtBob.add(u1.hash, u1.hash);
        await smtBob.add(u2.hash, u2.hash);
        await smtAlice.add(u1.hash, u1.hash);
        await smtAlice.add(u2.hash, u2.hash);

        const nullifier1 = newAssetNullifier(u1, Bob);
        const nullifier2 = newAssetNullifier(u2, Bob);
        const root = await smtBob.root();
        const p = await smtBob.generateCircomVerifierProof(u1.hash, root);
        const merkleProof = p.siblings.map((s) => s.bigInt());

        const lockedUtxo = newAssetUTXO(tokenId1, uri, Bob);
        // Borrow a real proof for the (u1 -> lockedUtxo) transition;
        // InvalidNonFungibleArity fires before the verifier is touched,
        // but the payload still has to be well-formed bytes.
        const { encodedProof } = await prepareProof(
          Bob,
          u1,
          nullifier1,
          lockedUtxo,
          root.bigInt(),
          merkleProof,
          Bob,
        );

        const createArgs = encodeCreateArgs({
          txId: randomBytes32(),
          // Two inputs: invalid for the NF lock circuit -- a single
          // token cannot be split.
          inputs: [nullifier1.hash, nullifier2.hash],
          outputs: [],
          lockedOutputs: [lockedUtxo.hash],
          proof: encodeUnlockedProof(root.bigInt(), encodedProof),
        });

        await expect(
          zeto
            .connect(Bob.signer)
            .createLock(createArgs, ethers.ZeroHash, ethers.ZeroHash, "0x"),
        )
          .to.be.revertedWithCustomError(zeto, "InvalidNonFungibleArity")
          .withArgs(2, 0, 1);
      }).timeout(600000);
    });
  });

  // --- helpers ---

  async function doTransfer(
    signer: User,
    input: UTXO,
    _nullifier: UTXO,
    output: UTXO,
    root: BigInt,
    merkleProof: BigInt[],
    owner: User,
  ) {
    const result = await prepareProof(
      signer,
      input,
      _nullifier,
      output,
      root,
      merkleProof,
      owner,
    );
    const txResult = await sendTx(
      signer,
      _nullifier.hash as BigNumberish,
      result.outputCommitment,
      root,
      result.encodedProof,
    );
    return { txResult };
  }

  // prepareProof builds a (root, ZkProof) bundle for the unlocked-input
  // transition using the `nf_anon_nullifier_transfer` circuit.
  async function prepareProof(
    signer: User,
    input: UTXO,
    _nullifier: UTXO,
    output: UTXO,
    root: BigInt,
    merkleProof: BigInt[],
    owner: User,
  ) {
    const nullifier = _nullifier.hash as BigNumberish;
    const inputCommitment: BigNumberish = input.hash as BigNumberish;
    const tokenId = BigInt(input.tokenId!);
    const tokenUri = tokenUriHash(input.uri!);
    const inputSalt = input.salt!;
    const outputCommitment: BigNumberish = output.hash as BigNumberish;
    const outputSalt = output.salt!;
    const outputOwnerPublicKey: [BigNumberish, BigNumberish] =
      owner.babyJubPublicKey as [BigNumberish, BigNumberish];

    const startWitnessCalculation = Date.now();
    const inputObj: any = {
      nullifier,
      inputCommitment,
      tokenId,
      tokenUri,
      inputSalt,
      inputOwnerPrivateKey: signer.formattedPrivateKey,
      root,
      merkleProof,
      outputCommitment,
      outputSalt,
      outputOwnerPublicKey,
    };
    const witness = await circuit.calculateWTNSBin(inputObj, true);
    const timeWitnessCalculation = Date.now() - startWitnessCalculation;

    const startProofGeneration = Date.now();
    const { proof } = (await groth16.prove(provingKey, witness)) as {
      proof: BigNumberish[];
      publicSignals: BigNumberish[];
    };
    const timeProofGeneration = Date.now() - startProofGeneration;

    logger.debug(
      `Witness calculation time: ${timeWitnessCalculation}ms. Proof generation time: ${timeProofGeneration}ms.`,
    );

    return {
      inputCommitment,
      outputCommitment,
      encodedProof: encodeProof(proof),
    };
  }

  // prepareLockedProof builds a ZkProof for the locked-input
  // transition using the simple `nf_anon` circuit. The locked input is
  // passed as a raw UTXO hash (not a nullifier); the contract's
  // {validateInputs(inputs, true)} confirms it sits in `_lockedUtxos`.
  async function prepareLockedProof(
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
    const witness = await circuitLocked.calculateWTNSBin(
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
    const { proof } = (await groth16.prove(provingKeyLocked, witness)) as {
      proof: BigNumberish[];
      publicSignals: BigNumberish[];
    };
    const timeProofGeneration = Date.now() - startProofGeneration;

    logger.debug(
      `Locked-witness calculation: ${timeWitnessCalculation}ms. Locked-proof generation: ${timeProofGeneration}ms.`,
    );

    return {
      inputCommitment,
      outputCommitment,
      encodedProof: encodeProof(proof),
    };
  }

  async function sendTx(
    signer: User,
    nullifier: BigNumberish,
    outputCommitment: BigNumberish,
    root: BigNumberish,
    encodedProof: any,
  ) {
    const startTx = Date.now();
    const tx = await zeto
      .connect(signer.signer)
      .transfer(
        nullifier,
        outputCommitment,
        encodeUnlockedProof(root, encodedProof),
        "0x",
      );
    const results: ContractTransactionReceipt | null = await tx.wait();
    logger.debug(
      `Time to execute transaction: ${Date.now() - startTx}ms. Gas used: ${
        results?.gasUsed
      }`,
    );
    return results;
  }
});

// Wire-format helpers. The unlocked branch carries `(root, ZkProof)`
// in the proof bytes; the locked branch carries just the ZkProof.
// These match the two `abi.decode` arms in
// {Zeto_NfAnonNullifier.constructPublicInputs}.
function encodeUnlockedProof(root: any, proof: any) {
  return new AbiCoder().encode(
    ["uint256 root", "tuple(uint256[2] pA, uint256[2][2] pB, uint256[2] pC)"],
    [root, proof],
  );
}

function encodeLockedProof(proof: any) {
  return new AbiCoder().encode(
    ["tuple(uint256[2] pA, uint256[2][2] pB, uint256[2] pC)"],
    [proof],
  );
}
