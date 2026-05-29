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
import {
  loadCircuit,
  poseidonDecrypt,
  encodeProof,
  Poseidon,
  newEncryptionNonce,
} from "zeto-js";
import { groth16 } from "snarkjs";
import {
  genKeypair,
  formatPrivKeyForBabyJub,
  genEcdhSharedKey,
  stringifyBigInts,
} from "maci-crypto";
import {
  User,
  UTXO,
  newUser,
  newUTXO,
  doMint,
  ZERO_UTXO,
  parseUTXOEvents,
  logger,
} from "./lib/utils";
import {
  loadProvingKeys,
  prepareDepositProof,
  prepareWithdrawProof,
  encodeToBytesForDeposit,
  calculateSpendHash,
  calculateCancelHash,
} from "./utils";
import { deployZeto } from "./lib/deploy";
const poseidonHash = Poseidon.poseidon4;

describe("Zeto based fungible token with anonymity and encryption", function () {
  let deployer: Signer;
  let Alice: User;
  let Bob: User;
  let Charlie: User;
  let erc20: any;
  let zeto: any;
  let utxo100: UTXO;
  let utxo1: UTXO;
  let utxo2: UTXO;
  let utxo3: UTXO;
  let utxo4: UTXO;
  let circuit: any, provingKey: any;
  let batchCircuit: any, batchProvingKey: any;

  before(async function () {
    // skip the tests if this file is being imported from another test
    // module solely to access its exported `prepareProof` / `encodeToBytes`
    // helpers (mirrors the SKIP_ANON_TESTS pattern in `zeto_anon.ts`).
    if (process.env.SKIP_ANON_ENC_TESTS === "true") {
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

    ({ deployer, zeto, erc20 } = await deployZeto("Zeto_AnonEnc"));

    circuit = await loadCircuit("anon_enc");
    ({ provingKeyFile: provingKey } = loadProvingKeys("anon_enc"));
    batchCircuit = await loadCircuit("anon_enc_batch");
    ({ provingKeyFile: batchProvingKey } = loadProvingKeys("anon_enc_batch"));
  });

  beforeEach(async function () {
    if (process.env.SKIP_ANON_ENC_TESTS === "true") {
      this.skip();
    }
  });

  it("(batch) mint to Alice and batch transfer 10 UTXOs honestly to Bob & Charlie then withdraw should succeed", async function () {
    // first mint the tokens for batch testing
    const inputUtxos = [];
    for (let i = 0; i < 10; i++) {
      // mint 10 utxos
      inputUtxos.push(newUTXO(1, Alice));
    }
    await doMint(zeto, deployer, inputUtxos);

    const aliceUTXOsToBeWithdrawn = [
      newUTXO(1, Alice),
      newUTXO(1, Alice),
      newUTXO(1, Alice),
    ];
    // Alice proposes the output UTXOs, 1 utxo to bob, 1 utxo to charlie and 3 utxos to alice
    const _bOut1 = newUTXO(6, Bob);
    const _bOut2 = newUTXO(1, Charlie);

    const outputUtxos = [_bOut1, _bOut2, ...aliceUTXOsToBeWithdrawn];
    const outputOwners = [Bob, Charlie, Alice, Alice, Alice];
    const inflatedOutputUtxos = [...outputUtxos];
    const inflatedOutputOwners = [...outputOwners];
    for (let i = 0; i < 10 - outputUtxos.length; i++) {
      inflatedOutputUtxos.push(ZERO_UTXO);
      inflatedOutputOwners.push(Bob);
    }

    // Alice transfers UTXOs to Bob
    const result = await doTransfer(
      Alice,
      inputUtxos,
      inflatedOutputUtxos,
      inflatedOutputOwners,
    );

    const events = parseUTXOEvents(zeto, result.txResult!);
    const event = events[0];
    expect(event.inputs).to.deep.equal(inputUtxos.map((i) => i.hash));
    const incomingUTXOs: any = event.outputs;
    const ecdhPublicKey = event.ecdhPublicKey;

    // check the non-empty output hashes are correct
    for (let i = 0; i < outputUtxos.length; i++) {
      const utxoOwner = outputOwners[i];
      const sharedKey = genEcdhSharedKey(
        utxoOwner.babyJubPrivateKey,
        ecdhPublicKey,
      );
      const plainText = poseidonDecrypt(
        event.encryptedValues.slice(4 * i, 4 * i + 4),
        sharedKey,
        event.encryptionNonce,
        2,
      );
      expect(plainText).to.deep.equal(
        result.expectedPlainText.slice(2 * i, 2 * i + 2),
      );
      const hash = poseidonHash([
        BigInt(plainText[0]),
        plainText[1],
        utxoOwner.babyJubPublicKey[0],
        utxoOwner.babyJubPublicKey[1],
      ]);
      expect(incomingUTXOs[i]).to.equal(hash);
    }

    // mint sufficient balance in Zeto contract address for Alice to withdraw
    const mintTx = await erc20.connect(deployer).mint(zeto, 3);
    await mintTx.wait();
    const startingBalance = await erc20.balanceOf(Alice.ethAddress);

    // Alice generates the nullifiers for the UTXOs to be spent
    const inflatedWithdrawInputs = [...aliceUTXOsToBeWithdrawn];

    // Alice generates inclusion proofs for the UTXOs to be spent

    for (let i = aliceUTXOsToBeWithdrawn.length; i < 10; i++) {
      inflatedWithdrawInputs.push(ZERO_UTXO);
    }
    const { inputCommitments, outputCommitments, encodedProof } =
      await prepareWithdrawProof(Alice, inflatedWithdrawInputs, ZERO_UTXO);

    // Alice withdraws her UTXOs to ERC20 tokens
    const tx = await zeto
      .connect(Alice.signer)
      .withdraw(
        3,
        inputCommitments,
        outputCommitments[0],
        encodeToBytesForWithdraw(encodedProof),
        "0x",
      );
    await tx.wait();

    // Alice checks her ERC20 balance
    const endingBalance = await erc20.balanceOf(Alice.ethAddress);
    expect(endingBalance - startingBalance).to.be.equal(3);
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
      .deposit(
        100,
        outputCommitments,
        encodeToBytesForDeposit(encodedProof),
        "0x",
      );
    await tx2.wait();
  }).timeout(60000);

  it("mint to Alice and transfer UTXOs honestly to Bob should succeed", async function () {
    const startingBalance = await erc20.balanceOf(Alice.ethAddress);
    // first the authority mints UTXOs to Alice
    utxo1 = newUTXO(10, Alice);
    utxo2 = newUTXO(20, Alice);
    await doMint(zeto, deployer, [utxo1, utxo2]);

    // check the private mint activity is not exposed in the ERC20 contract
    const afterMintBalance = await erc20.balanceOf(Alice.ethAddress);
    expect(afterMintBalance).to.equal(startingBalance);

    // Alice proposes the output UTXOs
    const _utxo1 = newUTXO(25, Bob);
    utxo4 = newUTXO(5, Alice, _utxo1.salt);

    // Alice transfers UTXOs to Bob
    const result = await doTransfer(
      Alice,
      [utxo1, utxo2],
      [_utxo1, utxo4],
      [Bob, Alice],
    );

    // check the private transfer activity is not exposed in the ERC20 contract
    const afterTransferBalance = await erc20.balanceOf(Alice.ethAddress);
    expect(afterTransferBalance).to.equal(startingBalance);

    // Bob uses the information in the event to recover the incoming UTXO
    // first obtain the UTXO from the transaction event
    const events = parseUTXOEvents(zeto, result.txResult!);
    const event = events[0];
    expect(event.inputs).to.deep.equal([utxo1.hash, utxo2.hash]);
    expect(event.outputs).to.deep.equal([_utxo1.hash, utxo4.hash]);
    const incomingUTXOs: any = event.outputs;

    const ecdhPublicKey = event.ecdhPublicKey;
    // Bob reconstructs the shared key using his private key and ephemeral public key

    const sharedKey = genEcdhSharedKey(Bob.babyJubPrivateKey, ecdhPublicKey);
    const plainText = poseidonDecrypt(
      event.encryptedValues.slice(0, 4),
      sharedKey,
      event.encryptionNonce,
      2,
    );
    expect(plainText).to.deep.equal(result.expectedPlainText.slice(0, 2));
    // Bob verifies that the UTXO constructed from the decrypted values matches the UTXO from the event
    const hash = poseidonHash([
      BigInt(plainText[0]),
      plainText[1],
      Bob.babyJubPublicKey[0],
      Bob.babyJubPublicKey[1],
    ]);
    expect(hash).to.equal(incomingUTXOs[0]);

    // simulate Bob using the decrypted values to construct the UTXO received from the transaction
    utxo3 = newUTXO(Number(plainText[0]), Bob, plainText[1]);
  });

  it("Bob transfers UTXOs, previously received from Alice, honestly to Charlie should succeed", async function () {
    // propose the output UTXOs
    const _utxo1 = newUTXO(25, Charlie);
    // Bob should be able to spend the UTXO that was reconstructed from the previous transaction
    await doTransfer(
      Bob,
      [utxo3, ZERO_UTXO],
      [_utxo1, ZERO_UTXO],
      [Charlie, Bob],
    );
  });

  it("Alice withdraws her UTXOs to ERC20 tokens should succeed", async function () {
    const startingBalance = await erc20.balanceOf(Alice.ethAddress);
    // Alice proposes the output ERC20 tokens
    const outputCommitment = newUTXO(20, Alice);

    const { inputCommitments, outputCommitments, encodedProof } =
      await prepareWithdrawProof(Alice, [utxo100, ZERO_UTXO], outputCommitment);

    // Alice withdraws her UTXOs to ERC20 tokens
    const tx = await zeto
      .connect(Alice.signer)
      .withdraw(
        80,
        inputCommitments,
        outputCommitments[0],
        encodeToBytesForWithdraw(encodedProof),
        "0x",
      );
    await tx.wait();

    // Alice checks her ERC20 balance
    const endingBalance = await erc20.balanceOf(Alice.ethAddress);
    expect(endingBalance - startingBalance).to.be.equal(80);
  });

  describe("failure cases", function () {
    // the following failure cases rely on the hardhat network
    // to return the details of the errors. This is not possible
    // on non-hardhat networks
    if (network.name !== "hardhat") {
      return;
    }

    it("Alice attempting to withdraw spent UTXOs should fail", async function () {
      // Alice proposes the output ERC20 tokens
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
            encodeToBytesForWithdraw(encodedProof),
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
      // create outputs
      const _utxo1 = newUTXO(25, Bob);
      const _utxo2 = newUTXO(5, Alice);
      await expect(
        doTransfer(Alice, [utxo1, utxo2], [_utxo1, _utxo2], [Bob, Alice]),
      ).rejectedWith("UTXOAlreadySpent");
    });

    it("spend by using the same UTXO as both inputs should fail", async function () {
      // mint a new UTXO to Bob
      const _utxo1 = newUTXO(20, Bob);
      await doMint(zeto, deployer, [_utxo1]);

      const _utxo2 = newUTXO(25, Alice);
      const _utxo3 = newUTXO(15, Bob);
      await expect(
        doTransfer(Bob, [_utxo1, _utxo1], [_utxo2, _utxo3], [Alice, Bob]),
      ).rejectedWith(`UTXODuplicate(${_utxo1.hash.toString()}`);
    });
  });

  describe("ILockableCapability tests", function () {
    // ABI fragments for the ZetoLockableCapability *Args payloads. These
    // mirror the layout used in `zeto_anon.ts` / `zeto_anon_nullifier.ts`
    // so that the cross-token contract surface stays uniform — the only
    // thing that changes for the encryption-aware token is what goes
    // inside the opaque `proof` blob (we wrap the Groth16 proof with the
    // ECDH key, encryption nonce and encrypted values via
    // `encodeToBytes` below).
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

    // prepareEncProofBytes wraps `prepareProof` to return ABI-encoded
    // proof bytes ready to be slotted into createArgs / spendArgs.
    // `Zeto_AnonEnc.constructPublicInputs` expects the proof tuple
    // (uint256, uint256[2], uint256[], Commonlib.Proof) — same layout
    // as the regular `transfer` flow — so the locked-input path reuses
    // the same proof builder.
    async function prepareEncProofBytes(
      signer: User,
      inputs: UTXO[],
      outputs: UTXO[],
      owners: User[],
    ): Promise<string> {
      const ephemeralKeypair = genKeypair();
      const result = await prepareProof(
        signer,
        inputs,
        outputs,
        owners,
        ephemeralKeypair.privKey,
      );
      return encodeToBytes(
        result.encryptionNonce,
        ephemeralKeypair.pubKey,
        result.encryptedValues,
        result.encodedProof,
      );
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
        // before constructPublicInputs), so the same anon_enc circuit is
        // reused.
        lockedUtxo = newUTXO(bobSourceUtxo.value!, Bob);
        const proofBytes = await prepareEncProofBytes(
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
          proof: proofBytes,
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
        expect(await zeto.locked(lockedUtxo.hash)).to.deep.equal([
          true,
          Alice.ethAddress,
        ]);
      });

      it("the new spender can spendLock() with the matching payload", async function () {
        // Bob (still the original owner of the locked UTXO) generates the
        // settlement proof; Alice (the new spender) submits it.
        const settleProofBytes = await prepareEncProofBytes(
          Bob,
          [lockedUtxo, ZERO_UTXO],
          [outUtxo1, outUtxo2],
          [Alice, Bob],
        );

        const spendArgs = encodeSpendArgs({
          txId: randomBytes32(),
          lockedOutputs: [],
          outputs: [outUtxo1.hash, outUtxo2.hash],
          proof: settleProofBytes,
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
        const proofBytes = await prepareEncProofBytes(
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
          proof: proofBytes,
        });
        lockId = await zeto.connect(Bob.signer).computeLockId(createArgs);
        const tx = await zeto
          .connect(Bob.signer)
          .createLock(createArgs, ethers.ZeroHash, cancelHash, "0x");
        const result = await tx.wait();
        logger.debug(`createLock() complete. Gas used: ${result?.gasUsed}`);
      });

      it("the owner can cancelLock() to reverse the lock without delegation", async function () {
        const cancelProofBytes = await prepareEncProofBytes(
          Bob,
          [lockedUtxo, ZERO_UTXO],
          [outUtxo1, outUtxo2],
          [Alice, Bob],
        );

        const cancelArgs = encodeSpendArgs({
          txId: randomBytes32(),
          lockedOutputs: [],
          outputs: [outUtxo1.hash, outUtxo2.hash],
          proof: cancelProofBytes,
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
        const zetoCancelled = parsed.find(
          (p) => p.name === "ZetoLockCancelled",
        );
        expect(cancelled, "LockCancelled event not emitted").to.not.be
          .undefined;
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
        const proofBytes = await prepareEncProofBytes(
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
          proof: proofBytes,
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

        const settleProofBytes = await prepareEncProofBytes(
          Bob,
          [lockedUtxo, ZERO_UTXO],
          [wrongOut1, wrongOut2],
          [Alice, Bob],
        );

        const spendArgs = encodeSpendArgs({
          txId: randomBytes32(),
          lockedOutputs: [],
          outputs: [wrongOut1.hash, wrongOut2.hash],
          proof: settleProofBytes,
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
        const proofBytes = await prepareEncProofBytes(
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
          proof: proofBytes,
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
        const settleProofBytes = await prepareEncProofBytes(
          Bob,
          [lockedUtxo, ZERO_UTXO],
          [out1, out2],
          [Alice, Bob],
        );
        const spendArgs = encodeSpendArgs({
          txId: randomBytes32(),
          lockedOutputs: [],
          outputs: [out1.hash, out2.hash],
          proof: settleProofBytes,
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
    let encryptedValues: BigNumberish[];
    let encryptionNonce: BigNumberish;
    let encodedProof: any;
    const ephemeralKeypair = genKeypair();
    const result = await prepareProof(
      signer,
      inputs,
      outputs,
      owners,
      ephemeralKeypair.privKey,
    );
    inputCommitments = result.inputCommitments;
    outputCommitments = result.outputCommitments;
    encodedProof = result.encodedProof;
    encryptedValues = result.encryptedValues;
    encryptionNonce = result.encryptionNonce;

    const txResult = await sendTx(
      signer,
      inputCommitments,
      outputCommitments,
      encryptedValues,
      encryptionNonce,
      encodedProof,
      ephemeralKeypair.pubKey,
    );
    // add the clear text value so that it can be used by tests to compare with the decrypted value
    return {
      txResult,
      expectedPlainText: outputs.reduce((acc, o, i) => {
        acc.push(BigInt(o.value || 0n) as BigNumberish);
        acc.push((o.salt || 0n) as BigNumberish);
        return acc;
      }, [] as BigNumberish[]),
    };
  }

  async function prepareProof(
    signer: User,
    inputs: UTXO[],
    outputs: UTXO[],
    owners: User[],
    ephemeralPrivateKey: BigInt,
  ) {
    let circuitToUse = circuit;
    let provingKeyToUse = provingKey;
    if (inputs.length > 2 || outputs.length > 2) {
      circuitToUse = batchCircuit;
      provingKeyToUse = batchProvingKey;
    }
    return prepareProofModule(
      circuitToUse,
      provingKeyToUse,
      signer,
      inputs,
      outputs,
      owners,
      ephemeralPrivateKey,
    );
  }

  async function sendTx(
    signer: User,
    inputCommitments: BigNumberish[],
    outputCommitments: BigNumberish[],
    encryptedValues: BigNumberish[],
    encryptionNonce: BigNumberish,
    encodedProof: any,
    ecdhPublicKey: BigInt[],
  ) {
    const tx = await zeto.connect(signer.signer).transfer(
      inputCommitments.filter((ic) => ic !== 0n), // trim off empty utxo hashes to check padding logic for batching works
      outputCommitments.filter((oc) => oc !== 0n), // trim off empty utxo hashes to check padding logic for batching works
      encodeToBytes(
        encryptionNonce,
        ecdhPublicKey,
        encryptedValues,
        encodedProof,
      ),
      "0x",
    );
    const results: ContractTransactionReceipt | null = await tx.wait();

    for (const input of inputCommitments) {
      if (input === 0n) continue;
      expect(await zeto.spent(input)).to.equal(2n);
    }
    for (const output of outputCommitments) {
      if (output === 0n) continue;
      expect(await zeto.spent(output)).to.equal(1n);
    }
    console.log(`Method transfer() complete. Gas used: ${results?.gasUsed}`);

    return results;
  }
});

function encodeToBytes(
  encryptionNonce: any,
  ecdhPublicKey: any,
  encryptedValues: any,
  proof: any,
) {
  const bytes = new AbiCoder().encode(
    [
      "uint256 encryptionNonce",
      "uint256[2] ecdhPublicKey",
      "uint256[] encryptedValues",
      "tuple(uint256[2] pA, uint256[2][2] pB, uint256[2] pC)",
    ],
    [encryptionNonce, ecdhPublicKey, encryptedValues, proof],
  );
  // console.log("Encryption nonce:", encryptionNonce);
  // console.log("ECDH public key:", ecdhPublicKey);
  // console.log("Encrypted values:", encryptedValues);
  // console.log("Proof:", proof);
  // console.log("Encoded proof:", bytes);
  return bytes;
}

function encodeToBytesForWithdraw(proof: any) {
  return new AbiCoder().encode(
    ["tuple(uint256[2] pA, uint256[2][2] pB, uint256[2] pC)"],
    [proof],
  );
}

// Module-scope twin of the in-describe `prepareProof`. Lifted so that other
// test suites (notably `zeto_anon_enc_nullifier.ts`) can reuse it for
// locked-input proofs that need to verify against the `anon_enc` circuit
// rather than a nullifier-aware encryption circuit. Mirrors the
// {prepareProof,encodeToBytes} export pattern at the bottom of
// `zeto_anon.ts`.
async function prepareProofModule(
  circuit: any,
  provingKey: any,
  signer: User,
  inputs: UTXO[],
  outputs: UTXO[],
  owners: User[],
  ephemeralPrivateKey: BigInt,
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
  const outputOwnerPublicKeys: BigNumberish[][] = owners.map(
    (owner) => owner.babyJubPublicKey,
  ) as BigNumberish[][];
  const encryptionNonce: BigNumberish = newEncryptionNonce() as BigNumberish;
  const encryptInputs = stringifyBigInts({
    encryptionNonce,
    ecdhPrivateKey: formatPrivKeyForBabyJub(ephemeralPrivateKey),
  });

  const startWitnessCalculation = Date.now();
  const witness = await circuit.calculateWTNSBin(
    {
      inputCommitments,
      inputValues,
      inputSalts,
      inputOwnerPrivateKey: formatPrivKeyForBabyJub(signer.babyJubPrivateKey),
      outputCommitments,
      outputValues,
      outputSalts: outputs.map((output) => output.salt || 0n),
      outputOwnerPublicKeys,
      ...encryptInputs,
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
  console.log(
    `Witness calculation time: ${timeWitnessCalculation}ms, Proof generation time: ${timeProofGeneration}ms`,
  );

  // The encryption circuit emits 4 encrypted-values per output commitment
  // (poseidon-cipher chunked into 4 field elements). publicSignals[0..2]
  // are the ECDH public key, so the encrypted blob starts at index 2.
  const encryptedValues = publicSignals.slice(2, 2 + 4 * outputs.length);
  const encodedProof = encodeProof(proof);
  return {
    inputCommitments,
    outputCommitments,
    encryptedValues,
    encryptionNonce,
    encodedProof,
  };
}

module.exports = {
  prepareProof: prepareProofModule,
  encodeToBytes,
};
