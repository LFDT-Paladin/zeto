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
import { Merkletree, InMemoryDB, str2Bytes } from "@iden3/js-merkletree";
import {
  UTXO,
  User,
  newUser,
  newUTXO,
  newNullifier,
  doMint,
  ZERO_UTXO,
  parseUTXOEvents,
  logger,
} from "./lib/utils";
import {
  loadProvingKeys,
  prepareDepositProof,
  prepareNullifierWithdrawProof,
  encodeToBytesForDeposit,
  encodeToBytesForWithdraw,
  calculateSpendHash,
  calculateCancelHash,
} from "./utils";
process.env.SKIP_ANON_ENC_TESTS = "true";
import {
  prepareProof as prepareProofForLockedEnc,
  encodeToBytes as encodeToBytesForLockedEnc,
} from "./zeto_anon_enc";
import { deployZeto } from "./lib/deploy";
import { describeZetoToken } from "./lib/eip170";
const poseidonHash = Poseidon.poseidon4;

describeZetoToken(
  "Zeto_AnonEncNullifier",
  "Zeto based fungible token with anonymity using nullifiers and encryption",
  function () {
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
  let utxo7: UTXO;
  let circuit: any, provingKey: any;
  let circuitForLocked: any, provingKeyForLocked: any;
  let batchCircuit: any, batchProvingKey: any;
  let smtAlice: Merkletree;
  let smtBob: Merkletree;

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

    ({ deployer, zeto, erc20 } = await deployZeto("Zeto_AnonEncNullifier"));

    const storage1 = new InMemoryDB(str2Bytes(""));
    smtAlice = new Merkletree(storage1, true, 64);

    const storage2 = new InMemoryDB(str2Bytes(""));
    smtBob = new Merkletree(storage2, true, 64);

    circuit = await loadCircuit("anon_enc_nullifier");
    ({ provingKeyFile: provingKey } = loadProvingKeys("anon_enc_nullifier"));
    batchCircuit = await loadCircuit("anon_enc_nullifier_batch");
    ({ provingKeyFile: batchProvingKey } = loadProvingKeys(
      "anon_enc_nullifier_batch",
    ));
    // For consuming locked UTXOs we use the non-nullifier `anon_enc`
    // circuit. Rationale (mirrors {Zeto_AnonNullifier}): under the
    // ILockableCapability storage, locked UTXOs live in a flat per-lock
    // mapping with no SMT or nullifier history, so the locked-input proof
    // has nothing to bind against on the nullifier side. The encryption
    // witness is still required (receiver data availability), so we use
    // `anon_enc` rather than the plain `anon` circuit. The contract's
    // {constructPublicInputs(..., inputsLocked = true)} emits the
    // `[ecdhPublicKey, encryptedValues, inputs, outputs, encryptionNonce]`
    // layout that `Groth16Verifier_AnonEnc` expects.
    circuitForLocked = await loadCircuit("anon_enc");
    ({ provingKeyFile: provingKeyForLocked } = loadProvingKeys("anon_enc"));
  });

  it("onchain SMT root should be equal to the offchain SMT root", async function () {
    const root = await smtAlice.root();
    const onchainRoot = await zeto.getRoot();
    expect(onchainRoot).to.equal(0n);
    expect(root.string()).to.equal(onchainRoot.toString());
  });

  it("(batch) mint to Alice and batch transfer 10 UTXOs honestly to Bob & Charlie then withdraw should succeed", async function () {
    // first mint the tokens for batch testing
    const inputUtxos = [];
    const nullifiers = [];
    for (let i = 0; i < 10; i++) {
      // mint 10 utxos
      const _utxo = newUTXO(1, Alice);
      nullifiers.push(newNullifier(_utxo, Alice));
      inputUtxos.push(_utxo);
    }
    const mintResult = await doMint(zeto, deployer, inputUtxos);

    const mintEvents = parseUTXOEvents(zeto, mintResult);
    const mintedHashes = mintEvents[0].outputs;
    for (let i = 0; i < mintedHashes.length; i++) {
      if (mintedHashes[i] !== 0) {
        await smtAlice.add(mintedHashes[i], mintedHashes[i]);
        await smtBob.add(mintedHashes[i], mintedHashes[i]);
      }
    }
    // Alice generates inclusion proofs for the UTXOs to be spent
    let root = await smtAlice.root();
    const mtps = [];
    for (let i = 0; i < inputUtxos.length; i++) {
      const p = await smtAlice.generateCircomVerifierProof(
        inputUtxos[i].hash,
        root,
      );
      mtps.push(p.siblings.map((s) => s.bigInt()));
    }

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
    // Alice transfers her UTXOs to Bob
    const result = await doTransfer(
      Alice,
      inputUtxos,
      nullifiers,
      inflatedOutputUtxos,
      root.bigInt(),
      mtps,
      inflatedOutputOwners,
    );

    const signerAddress = await Alice.signer.getAddress();
    const events = parseUTXOEvents(zeto, result.txResult!);
    const event = events[0];
    expect(event.submitter).to.equal(signerAddress);
    expect(event.inputs).to.deep.equal(nullifiers.map((n) => n.hash));

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
      await smtAlice.add(incomingUTXOs[i], incomingUTXOs[i]);
      await smtBob.add(incomingUTXOs[i], incomingUTXOs[i]);
    }

    // mint sufficient balance in Zeto contract address for Alice to withdraw
    const mintTx = await erc20.connect(deployer).mint(zeto, 3);
    await mintTx.wait();
    const startingBalance = await erc20.balanceOf(Alice.ethAddress);

    // Alice generates the nullifiers for the UTXOs to be spent
    root = await smtAlice.root();
    const inflatedWithdrawNullifiers = [];
    const inflatedWithdrawInputs = [];
    const inflatedWithdrawMTPs = [];
    for (let i = 0; i < aliceUTXOsToBeWithdrawn.length; i++) {
      inflatedWithdrawInputs.push(aliceUTXOsToBeWithdrawn[i]);
      inflatedWithdrawNullifiers.push(
        newNullifier(aliceUTXOsToBeWithdrawn[i], Alice),
      );
      const _withdrawUTXOProof = await smtAlice.generateCircomVerifierProof(
        aliceUTXOsToBeWithdrawn[i].hash,
        root,
      );
      inflatedWithdrawMTPs.push(
        _withdrawUTXOProof.siblings.map((s) => s.bigInt()),
      );
    }
    // Alice generates inclusion proofs for the UTXOs to be spent

    for (let i = aliceUTXOsToBeWithdrawn.length; i < 10; i++) {
      inflatedWithdrawInputs.push(ZERO_UTXO);
      inflatedWithdrawNullifiers.push(ZERO_UTXO);
      const _zeroProof = await smtAlice.generateCircomVerifierProof(0n, root);
      inflatedWithdrawMTPs.push(_zeroProof.siblings.map((s) => s.bigInt()));
    }

    const {
      nullifiers: _withdrawNullifiers,
      outputCommitments: withdrawCommitments,
      encodedProof: withdrawEncodedProof,
    } = await prepareNullifierWithdrawProof(
      Alice,
      inflatedWithdrawInputs,
      inflatedWithdrawNullifiers,
      ZERO_UTXO,
      root.bigInt(),
      inflatedWithdrawMTPs,
    );

    // Alice withdraws her UTXOs to ERC20 tokens
    const tx = await zeto
      .connect(Alice.signer)
      .withdraw(
        3,
        _withdrawNullifiers,
        withdrawCommitments[0],
        encodeToBytesForWithdraw(root.bigInt(), withdrawEncodedProof),
        "0x",
      );
    await tx.wait();

    // Alice checks her ERC20 balance
    const endingBalance = await erc20.balanceOf(Alice.ethAddress);
    expect(endingBalance - startingBalance).to.be.equal(3);
  }).timeout(180000);

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

    await smtAlice.add(utxo100.hash, utxo100.hash);
    await smtAlice.add(utxo0.hash, utxo0.hash);
    await smtBob.add(utxo100.hash, utxo100.hash);
    await smtBob.add(utxo0.hash, utxo0.hash);
  });

  it("mint to Alice and transfer UTXOs honestly to Bob should succeed", async function () {
    const startingBalance = await erc20.balanceOf(Alice.ethAddress);
    // The authority mints a new UTXO and assigns it to Alice
    utxo1 = newUTXO(10, Alice);
    utxo2 = newUTXO(20, Alice);
    const result1 = await doMint(zeto, deployer, [utxo1, utxo2]);

    // check the private mint activity is not exposed in the ERC20 contract
    const afterMintBalance = await erc20.balanceOf(Alice.ethAddress);
    expect(afterMintBalance).to.equal(startingBalance);

    // Alice locally tracks the UTXOs inside the Sparse Merkle Tree
    // hardhat doesn't have a good way to subscribe to events so we have to parse the Tx result object
    const mintEvents = parseUTXOEvents(zeto, result1);
    const [_utxo1, _utxo2] = mintEvents[0].outputs;
    await smtAlice.add(_utxo1, _utxo1);
    await smtAlice.add(_utxo2, _utxo2);
    let root = await smtAlice.root();
    let onchainRoot = await zeto.getRoot();
    expect(root.string()).to.equal(onchainRoot.toString());
    // Bob also locally tracks the UTXOs inside the Sparse Merkle Tree
    await smtBob.add(_utxo1, _utxo1);
    await smtBob.add(_utxo2, _utxo2);

    // Alice proposes the output UTXOs for the transfer to Bob
    const _utxo3 = newUTXO(25, Bob);
    utxo4 = newUTXO(5, Alice);

    // Alice generates the nullifiers for the UTXOs to be spent
    const nullifier1 = newNullifier(utxo1, Alice);
    const nullifier2 = newNullifier(utxo2, Alice);

    // Alice generates inclusion proofs for the UTXOs to be spent
    const proof1 = await smtAlice.generateCircomVerifierProof(utxo1.hash, root);
    const proof2 = await smtAlice.generateCircomVerifierProof(utxo2.hash, root);
    const merkleProofs = [
      proof1.siblings.map((s) => s.bigInt()),
      proof2.siblings.map((s) => s.bigInt()),
    ];

    // Alice transfers her UTXOs to Bob
    const result2 = await doTransfer(
      Alice,
      [utxo1, utxo2],
      [nullifier1, nullifier2],
      [_utxo3, utxo4],
      root.bigInt(),
      merkleProofs,
      [Bob, Alice],
    );

    // check the private transfer activity is not exposed in the ERC20 contract
    const afterTransferBalance = await erc20.balanceOf(Alice.ethAddress);
    expect(afterTransferBalance).to.equal(startingBalance);

    // Alice locally tracks the UTXOs inside the Sparse Merkle Tree
    await smtAlice.add(_utxo3.hash, _utxo3.hash);
    await smtAlice.add(utxo4.hash, utxo4.hash);
    root = await smtAlice.root();
    onchainRoot = await zeto.getRoot();
    expect(root.string()).to.equal(onchainRoot.toString());

    // Bob locally tracks the UTXOs inside the Sparse Merkle Tree
    // Bob parses the UTXOs from the onchain event
    const signerAddress = await Alice.signer.getAddress();
    const events = parseUTXOEvents(zeto, result2.txResult!);
    const event = events[0];
    expect(event.submitter).to.equal(signerAddress);
    expect(event.inputs).to.deep.equal([nullifier1.hash, nullifier2.hash]);
    expect(event.outputs).to.deep.equal([_utxo3.hash, utxo4.hash]);
    await smtBob.add(event.outputs[0], event.outputs[0]);
    await smtBob.add(event.outputs[1], event.outputs[1]);

    const ecdhPublicKey = event.ecdhPublicKey;
    // Bob reconstructs the shared key using his private key and ephemeral public key

    const sharedKey = genEcdhSharedKey(Bob.babyJubPrivateKey, ecdhPublicKey);
    const plainText = poseidonDecrypt(
      event.encryptedValues.slice(0, 4),
      sharedKey,
      event.encryptionNonce,
      2,
    );
    expect(plainText).to.deep.equal(result2.expectedPlainText.slice(0, 2));

    // Bob uses the decrypted values to construct the UTXO received from the transaction
    utxo3 = newUTXO(Number(plainText[0]), Bob, plainText[1]);
  }).timeout(600000);

  it("Bob transfers UTXOs, previously received from Alice, honestly to Charlie should succeed", async function () {
    // Bob generates the nullifiers for the UTXO to be spent
    const nullifier1 = newNullifier(utxo3, Bob);

    // Bob generates inclusion proofs for the UTXOs to be spent, as private input to the proof generation
    const root = await smtBob.root();
    const proof1 = await smtBob.generateCircomVerifierProof(utxo3.hash, root);
    const proof2 = await smtBob.generateCircomVerifierProof(0n, root);
    const merkleProofs = [
      proof1.siblings.map((s) => s.bigInt()),
      proof2.siblings.map((s) => s.bigInt()),
    ];

    // Bob proposes the output UTXOs
    const utxo6 = newUTXO(10, Charlie);
    utxo7 = newUTXO(15, Bob);

    // Bob should be able to spend the UTXO that was reconstructed from the previous transaction
    const result = await doTransfer(
      Bob,
      [utxo3, ZERO_UTXO],
      [nullifier1, ZERO_UTXO],
      [utxo6, utxo7],
      root.bigInt(),
      merkleProofs,
      [Charlie, Bob],
    );

    // Bob keeps the local SMT in sync
    await smtBob.add(utxo6.hash, utxo6.hash);
    await smtBob.add(utxo7.hash, utxo7.hash);

    // Alice gets the new UTXOs from the onchain event and keeps the local SMT in sync
    const events = parseUTXOEvents(zeto, result.txResult!);
    const event = events[0];
    await smtAlice.add(event.outputs[0], event.outputs[0]);
    await smtAlice.add(event.outputs[1], event.outputs[1]);
  }).timeout(600000);

  it("Alice withdraws her UTXOs to ERC20 tokens should succeed", async function () {
    const startingBalance = await erc20.balanceOf(Alice.ethAddress);

    // Alice generates the nullifiers for the UTXOs to be spent
    const nullifier1 = newNullifier(utxo100, Alice);

    // Alice generates inclusion proofs for the UTXOs to be spent
    let root = await smtAlice.root();
    const proof1 = await smtAlice.generateCircomVerifierProof(
      utxo100.hash,
      root,
    );
    const proof2 = await smtAlice.generateCircomVerifierProof(0n, root);
    const merkleProofs = [
      proof1.siblings.map((s) => s.bigInt()),
      proof2.siblings.map((s) => s.bigInt()),
    ];

    // Alice proposes the output ERC20 tokens
    const withdrawChangeUTXO = newUTXO(20, Alice);

    const { nullifiers, outputCommitments, encodedProof } =
      await prepareNullifierWithdrawProof(
        Alice,
        [utxo100, ZERO_UTXO],
        [nullifier1, ZERO_UTXO],
        withdrawChangeUTXO,
        root.bigInt(),
        merkleProofs,
      );

    // Alice withdraws her UTXOs to ERC20 tokens
    const tx = await zeto
      .connect(Alice.signer)
      .withdraw(
        80,
        nullifiers,
        outputCommitments[0],
        encodeToBytesForWithdraw(root.bigInt(), encodedProof),
        "0x",
      );
    await tx.wait();

    // Alice tracks the UTXO inside the SMT
    await smtAlice.add(withdrawChangeUTXO.hash, withdrawChangeUTXO.hash);
    // Bob also locally tracks the UTXOs inside the SMT
    await smtBob.add(withdrawChangeUTXO.hash, withdrawChangeUTXO.hash);

    // Alice checks her ERC20 balance
    const endingBalance = await erc20.balanceOf(Alice.ethAddress);
    expect(endingBalance - startingBalance).to.be.equal(80);
  });

  describe("ILockableCapability tests", function () {
    // ABI fragments for the ZetoLockableCapability *Args payloads.
    // Identical to the layout used by every other Zeto fungible token —
    // only the contents of the opaque `proof` blob differ between tokens.
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

    // prepareCreateLockProofBytes generates an `anon_enc_nullifier` proof
    // for the createLock transition `[sourceUtxo, ZERO] -> [lockedUtxo,
    // ZERO]`. The createLock path goes through
    // `constructPublicInputs(..., inputsLocked = false)` so we use the
    // standard nullifier-aware encryption circuit (same as a regular
    // unlocked transfer).
    async function prepareCreateLockProofBytes(
      signer: User,
      inputs: UTXO[],
      nullifiers: UTXO[],
      lockedOutputs: UTXO[],
      root: bigint,
      merkleProofs: BigInt[][],
      owners: User[],
    ): Promise<string> {
      const ephemeralKeypair = genKeypair();
      const result = await prepareProof(
        signer,
        inputs,
        nullifiers,
        lockedOutputs,
        root as unknown as BigInt,
        merkleProofs,
        owners,
        ephemeralKeypair.privKey,
      );
      return encodeToBytes(
        root,
        result.encryptionNonce,
        ephemeralKeypair.pubKey,
        result.encryptedValues,
        result.encodedProof,
      );
    }

    // prepareLockedSpendProofBytes generates a non-nullifier `anon_enc`
    // proof for a spendLock / cancelLock settlement. The contract's
    // locked-input verifier slot is wired to `Groth16Verifier_AnonEnc`,
    // so we go through the same code path that {Zeto_AnonEnc} uses for
    // its regular transfers — but wrap the result in the 5-tuple
    // `(root, encryptionNonce, ecdhPublicKey, encryptedValues, proof)`
    // that {Zeto_AnonEncNullifier.decodeProof_EncNullifier} expects. The
    // `root` field is decoded but ignored when `inputsLocked = true`, so
    // we pass 0n.
    async function prepareLockedSpendProofBytes(
      signer: User,
      lockedInputs: UTXO[],
      outputs: UTXO[],
      owners: User[],
    ): Promise<string> {
      const ephemeralKeypair = genKeypair();
      const result = await prepareProofForLockedEnc(
        circuitForLocked,
        provingKeyForLocked,
        signer,
        lockedInputs,
        outputs,
        owners,
        ephemeralKeypair.privKey,
      );
      return encodeToBytes(
        0n,
        result.encryptionNonce,
        ephemeralKeypair.pubKey,
        result.encryptedValues,
        result.encodedProof,
      );
    }

    describe("createLock -> updateLock -> delegateLock -> spendLock flow", function () {
      let bobUtxo1: UTXO;
      let aliceUtxo1: UTXO;
      let lockedUtxo1: UTXO;
      let lockId: string;
      let outputUtxo1: UTXO;
      let outputUtxo2: UTXO;
      let unlockHash: string;

      before(async function () {
        bobUtxo1 = newUTXO(100, Bob);
        await doMint(zeto, deployer, [bobUtxo1]);
        await smtAlice.add(bobUtxo1.hash, bobUtxo1.hash);
        await smtBob.add(bobUtxo1.hash, bobUtxo1.hash);

        aliceUtxo1 = newUTXO(100, Alice);
        await doMint(zeto, deployer, [aliceUtxo1]);
        await smtAlice.add(aliceUtxo1.hash, aliceUtxo1.hash);
        await smtBob.add(aliceUtxo1.hash, aliceUtxo1.hash);
      });

      it("createLock() with deterministic lockId computed from txId", async function () {
        const nullifier1 = newNullifier(bobUtxo1, Bob);
        lockedUtxo1 = newUTXO(bobUtxo1.value!, Bob);
        const root = await smtBob.root();
        const p1 = await smtBob.generateCircomVerifierProof(
          bobUtxo1.hash,
          root,
        );
        const p2 = await smtBob.generateCircomVerifierProof(0n, root);
        const merkleProofs = [
          p1.siblings.map((s) => s.bigInt()),
          p2.siblings.map((s) => s.bigInt()),
        ];
        const proofBytes = await prepareCreateLockProofBytes(
          Bob,
          [bobUtxo1, ZERO_UTXO],
          [nullifier1, ZERO_UTXO],
          [lockedUtxo1, ZERO_UTXO],
          root.bigInt(),
          merkleProofs,
          [Bob, Bob],
        );

        const txId = randomBytes32();
        const createArgs = encodeCreateArgs({
          txId,
          inputs: [nullifier1.hash],
          outputs: [],
          lockedOutputs: [lockedUtxo1.hash],
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
        expect(await zeto.locked(lockedUtxo1.hash)).to.deep.equal([
          true,
          Bob.ethAddress,
        ]);
        expect((await zeto.locked(aliceUtxo1.hash))[0]).to.be.false;
        expect((await zeto.locked(bobUtxo1.hash))[0]).to.be.false;
      });

      it("updateLock() commits the spend hash while owner == spender", async function () {
        outputUtxo1 = newUTXO(10, Alice);
        outputUtxo2 = newUTXO(90, Bob);

        unlockHash = calculateSpendHash(
          [lockedUtxo1],
          [],
          [outputUtxo1, outputUtxo2],
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
        const result: ContractTransactionReceipt | null = await tx.wait();
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
        const result: ContractTransactionReceipt | null = await tx.wait();
        logger.debug(`delegateLock() complete. Gas used: ${result?.gasUsed}`);

        const info = await zeto.getLock(lockId);
        expect(info.spender).to.equal(Alice.ethAddress);
        expect(await zeto.locked(lockedUtxo1.hash)).to.deep.equal([
          true,
          Alice.ethAddress,
        ]);
      });

      it("the new spender can spendLock() with the matching payload", async function () {
        const settleProofBytes = await prepareLockedSpendProofBytes(
          Bob,
          [lockedUtxo1, ZERO_UTXO],
          [outputUtxo1, outputUtxo2],
          [Alice, Bob],
        );

        const spendArgs = encodeSpendArgs({
          txId: randomBytes32(),
          lockedOutputs: [],
          outputs: [outputUtxo1.hash, outputUtxo2.hash],
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

        const outputs = zetoLockSpent!.args.outputs;
        await smtAlice.add(outputs[0], outputs[0]);
        await smtAlice.add(outputs[1], outputs[1]);
        await smtBob.add(outputs[0], outputs[0]);
        await smtBob.add(outputs[1], outputs[1]);

        expect(await zeto.isLockActive(lockId)).to.equal(false);
      });

      it("onchain SMT root for the unlocked UTXOs equals the offchain SMT root", async function () {
        const bobRoot = await smtBob.root();
        const aliceRoot = await smtAlice.root();
        const onchainRoot = await zeto.getRoot();
        expect(bobRoot.string()).to.equal(onchainRoot.toString());
        expect(aliceRoot.string()).to.equal(onchainRoot.toString());
      });
    });

    describe("createLock -> cancelLock flow", function () {
      let bobUtxo1: UTXO;
      let lockedUtxo1: UTXO;
      let lockId: string;
      let cancelHash: string;
      let outUtxo1: UTXO;
      let outUtxo2: UTXO;

      before(async function () {
        bobUtxo1 = newUTXO(100, Bob);
        await doMint(zeto, deployer, [bobUtxo1]);
        await smtAlice.add(bobUtxo1.hash, bobUtxo1.hash);
        await smtBob.add(bobUtxo1.hash, bobUtxo1.hash);
      });

      it("Bob createLock() with a non-zero cancelCommitment", async function () {
        const nullifier1 = newNullifier(bobUtxo1, Bob);
        lockedUtxo1 = newUTXO(bobUtxo1.value!, Bob);
        const root = await smtBob.root();
        const p1 = await smtBob.generateCircomVerifierProof(
          bobUtxo1.hash,
          root,
        );
        const p2 = await smtBob.generateCircomVerifierProof(0n, root);
        const merkleProofs = [
          p1.siblings.map((s) => s.bigInt()),
          p2.siblings.map((s) => s.bigInt()),
        ];
        const proofBytes = await prepareCreateLockProofBytes(
          Bob,
          [bobUtxo1, ZERO_UTXO],
          [nullifier1, ZERO_UTXO],
          [lockedUtxo1, ZERO_UTXO],
          root.bigInt(),
          merkleProofs,
          [Bob, Bob],
        );

        outUtxo1 = newUTXO(10, Alice);
        outUtxo2 = newUTXO(90, Bob);
        cancelHash = calculateCancelHash(
          [lockedUtxo1],
          [],
          [outUtxo1, outUtxo2],
          "0x",
        );

        const createArgs = encodeCreateArgs({
          txId: randomBytes32(),
          inputs: [nullifier1.hash],
          outputs: [],
          lockedOutputs: [lockedUtxo1.hash],
          proof: proofBytes,
        });
        lockId = await zeto.connect(Bob.signer).computeLockId(createArgs);
        const tx = await zeto
          .connect(Bob.signer)
          .createLock(createArgs, ethers.ZeroHash, cancelHash, "0x");
        const result: ContractTransactionReceipt | null = await tx.wait();
        logger.debug(`createLock() complete. Gas used: ${result?.gasUsed}`);
      });

      it("the owner can cancelLock() to reverse the lock without delegation", async function () {
        const cancelProofBytes = await prepareLockedSpendProofBytes(
          Bob,
          [lockedUtxo1, ZERO_UTXO],
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

        const outputs = zetoCancelled!.args.outputs;
        await smtAlice.add(outputs[0], outputs[0]);
        await smtAlice.add(outputs[1], outputs[1]);
        await smtBob.add(outputs[0], outputs[0]);
        await smtBob.add(outputs[1], outputs[1]);

        expect(await zeto.isLockActive(lockId)).to.equal(false);
      });

      it("onchain SMT root for the unlocked UTXOs equals the offchain SMT root", async function () {
        const bobRoot = await smtBob.root();
        const aliceRoot = await smtAlice.root();
        const onchainRoot = await zeto.getRoot();
        expect(bobRoot.string()).to.equal(onchainRoot.toString());
        expect(aliceRoot.string()).to.equal(onchainRoot.toString());
      });
    });

    describe("spendLock with a payload that does not match the spend commitment fails", function () {
      let bobUtxo1: UTXO;
      let lockedUtxo1: UTXO;
      let lockId: string;
      let expectedHash: string;

      before(async function () {
        bobUtxo1 = newUTXO(100, Bob);
        await doMint(zeto, deployer, [bobUtxo1]);
        await smtAlice.add(bobUtxo1.hash, bobUtxo1.hash);
        await smtBob.add(bobUtxo1.hash, bobUtxo1.hash);
      });

      it("Bob createLock() then updateLock() committing a specific spend hash", async function () {
        const nullifier1 = newNullifier(bobUtxo1, Bob);
        lockedUtxo1 = newUTXO(bobUtxo1.value!, Bob);
        const root = await smtBob.root();
        const p1 = await smtBob.generateCircomVerifierProof(
          bobUtxo1.hash,
          root,
        );
        const p2 = await smtBob.generateCircomVerifierProof(0n, root);
        const merkleProofs = [
          p1.siblings.map((s) => s.bigInt()),
          p2.siblings.map((s) => s.bigInt()),
        ];
        const proofBytes = await prepareCreateLockProofBytes(
          Bob,
          [bobUtxo1, ZERO_UTXO],
          [nullifier1, ZERO_UTXO],
          [lockedUtxo1, ZERO_UTXO],
          root.bigInt(),
          merkleProofs,
          [Bob, Bob],
        );

        const createArgs = encodeCreateArgs({
          txId: randomBytes32(),
          inputs: [nullifier1.hash],
          outputs: [],
          lockedOutputs: [lockedUtxo1.hash],
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
          [lockedUtxo1],
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

        const settleProofBytes = await prepareLockedSpendProofBytes(
          Bob,
          [lockedUtxo1, ZERO_UTXO],
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
          [lockedUtxo1],
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
      // without polluting other test scopes. Each call advances both
      // local SMTs to keep them in sync with the on-chain unlocked-UTXO
      // tree (the createLock proof needs a valid SMT inclusion proof).
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
        await smtAlice.add(sourceUtxo.hash, sourceUtxo.hash);
        await smtBob.add(sourceUtxo.hash, sourceUtxo.hash);

        const nullifier = newNullifier(sourceUtxo, owner);
        const lockedUtxo = newUTXO(sourceUtxo.value!, owner);
        const root = await smtBob.root();
        const p1 = await smtBob.generateCircomVerifierProof(
          sourceUtxo.hash,
          root,
        );
        const p2 = await smtBob.generateCircomVerifierProof(0n, root);
        const merkleProofs = [
          p1.siblings.map((s) => s.bigInt()),
          p2.siblings.map((s) => s.bigInt()),
        ];
        const proofBytes = await prepareCreateLockProofBytes(
          owner,
          [sourceUtxo, ZERO_UTXO],
          [nullifier, ZERO_UTXO],
          [lockedUtxo, ZERO_UTXO],
          root.bigInt(),
          merkleProofs,
          [owner, owner],
        );

        const createArgs = encodeCreateArgs({
          txId: randomBytes32(),
          inputs: [nullifier.hash],
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

      it("updateLock() after delegateLock() reverts with LockImmutable", async function () {
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
        const settleProofBytes = await prepareLockedSpendProofBytes(
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
        // Keep both SMTs in sync with the new unlocked outputs so
        // unrelated tests in later blocks can still reason about roots.
        await smtAlice.add(out1.hash, out1.hash);
        await smtAlice.add(out2.hash, out2.hash);
        await smtBob.add(out1.hash, out1.hash);
        await smtBob.add(out2.hash, out2.hash);

        expect(await zeto.isLockActive(lockId)).to.equal(false);
        await expect(zeto.getLock(lockId))
          .to.be.revertedWithCustomError(zeto, "LockNotActive")
          .withArgs(lockId);
        // Re-spending a consumed lock MUST also fail — lockActive is the
        // first modifier and emits LockNotActive before onlySpender.
        await expect(
          zeto.connect(Bob.signer).spendLock(lockId, dummySpendArgs(), "0x"),
        )
          .to.be.revertedWithCustomError(zeto, "LockNotActive")
          .withArgs(lockId);
      });
    });
  });

  // describe("legacy lockStates() tests, kept for reference", function () {
  //   let nullifier1: any;
  //   it("lockStates() should succeed when using unlocked states", async function () {
  //     nullifier1 = newNullifier(utxo4, Alice);
  //     const { nullifiers, encodedProof } = await prepareNullifiersLockProof(Alice, [nullifier1, ZERO_UTXO]);

  //     const tx = await zeto.connect(Alice.signer).lockStates(
  //       nullifiers.filter((ic) => ic !== 0n), // trim off empty utxo hashes to check padding logic for batching works
  //       encodedProof,
  //       Bob.ethAddress, // make Bob the delegate who can spend the state (if he has the right proof)
  //       "0x",
  //     );
  //     const results = await tx.wait();
  //     console.log(`Method transfer() complete. Gas used: ${results?.gasUsed}`);
  //   });

  //   it("lockStates() should fail when trying to lock as non-delegate", async function () {
  //     if (network.name !== "hardhat") {
  //       return;
  //     }

  //     // Bob is the owner of the UTXO, so he can generate the right proof
  //     const { nullifiers, encodedProof } = await prepareNullifiersLockProof(Alice, [nullifier1, ZERO_UTXO]);

  //     // but he's no longer the delegate (Alice is) to spend the state
  //     await expect(zeto.connect(Alice.signer).lockStates(
  //       nullifiers.filter((ic) => ic !== 0n), // trim off empty utxo hashes to check padding logic for batching works
  //       encodedProof,
  //       Alice.ethAddress,
  //       "0x",
  //     )).rejectedWith(`UTXOAlreadyLocked(${nullifier1.hash.toString()})`);
  //   });

  //   it("the original owner can NOT spend the locked state", async function () {
  //     // Alice generates inclusion proofs for the UTXOs to be spent, as private input to the proof generation
  //     const root = await smtAlice.root();
  //     const proof1 = await smtAlice.generateCircomVerifierProof(utxo4.hash, root);
  //     const proof2 = await smtAlice.generateCircomVerifierProof(0n, root);
  //     const merkleProofs = [
  //       proof1.siblings.map((s) => s.bigInt()),
  //       proof2.siblings.map((s) => s.bigInt()),
  //     ];

  //     // Alice proposes the output UTXOs, attempting to transfer to Charlie
  //     const utxo9 = newUTXO(5, Charlie);

  //     // Alice should NOT be able to spend the UTXO which has been locked and delegated to Bob
  //     await expect(doTransfer(
  //       Alice,
  //       [utxo4, ZERO_UTXO],
  //       [nullifier1, ZERO_UTXO],
  //       [utxo9, ZERO_UTXO],
  //       root.bigInt(),
  //       merkleProofs,
  //       [Charlie, Alice],
  //     )).to.be.rejectedWith("UTXOAlreadyLocked");
  //   });

  //   it("the original owner can NOT withdraw the locked state", async function () {
  //     // Alice generates inclusion proofs for the UTXOs to be spent, as private input to the proof generation
  //     const root = await smtAlice.root();
  //     const proof1 = await smtAlice.generateCircomVerifierProof(utxo4.hash, root);
  //     const proof2 = await smtAlice.generateCircomVerifierProof(0n, root);
  //     const merkleProofs = [
  //       proof1.siblings.map((s) => s.bigInt()),
  //       proof2.siblings.map((s) => s.bigInt()),
  //     ];

  //     const utxo9 = newUTXO(0, Alice);

  //     const { nullifiers, outputCommitments, encodedProof } =
  //       await prepareNullifierWithdrawProof(
  //         Alice,
  //         [utxo4, ZERO_UTXO],
  //         [nullifier1, ZERO_UTXO],
  //         utxo9,
  //         root.bigInt(),
  //         merkleProofs,
  //       );

  //     await expect(zeto
  //       .connect(Alice.signer)
  //       .withdraw(
  //         80,
  //         nullifiers,
  //         outputCommitments[0],
  //         root.bigInt(),
  //         encodedProof,
  //         "0x",
  //       )).to.be.rejectedWith("UTXOAlreadyLocked");
  //   });

  //   it("the designated delegate can use the proper proof to spend the locked state", async function () {
  //     // Alice generates inclusion proofs for the UTXOs to be spent, as private input to the proof generation
  //     const root = await smtAlice.root();
  //     const proof1 = await smtAlice.generateCircomVerifierProof(utxo4.hash, root);
  //     const proof2 = await smtAlice.generateCircomVerifierProof(0n, root);
  //     const merkleProofs = [
  //       proof1.siblings.map((s) => s.bigInt()),
  //       proof2.siblings.map((s) => s.bigInt()),
  //     ];

  //     // Alice proposes the output UTXOs, attempting to transfer to Charlie
  //     const utxo9 = newUTXO(5, Charlie);

  //     const ephemeralKeypair = genKeypair();
  //     const result = await prepareProof(
  //       Alice,
  //       [utxo4, ZERO_UTXO],
  //       [nullifier1, ZERO_UTXO],
  //       [utxo9, ZERO_UTXO],
  //       root.bigInt(),
  //       merkleProofs,
  //       [Charlie, Alice],
  //       ephemeralKeypair.privKey,
  //     );
  //     const nullifiers = [nullifier1.hash];

  //     // Bob (in reality this is usually a contract that orchestrates a trade flow) can spend the locked state
  //     // using the proof generated by the trade counterparty (Alice in this case)
  //     await expect(sendTx(
  //       Bob,
  //       nullifiers,
  //       result.outputCommitments,
  //       root.bigInt(),
  //       result.encryptedValues,
  //       result.encryptionNonce,
  //       result.encodedProof,
  //       ephemeralKeypair.pubKey,
  //     )).to.be.fulfilled;
  //   });
  // });

  describe("failure cases", function () {
    // the following failure cases rely on the hardhat network
    // to return the details of the errors. This is not possible
    // on non-hardhat networks
    if (network.name !== "hardhat") {
      return;
    }

    it("Alice attempting to withdraw spent UTXOs should fail", async function () {
      // Alice generates the nullifiers for the UTXOs to be spent
      const nullifier1 = newNullifier(utxo100, Alice);

      // Alice generates inclusion proofs for the UTXOs to be spent
      let root = await smtAlice.root();
      const proof1 = await smtAlice.generateCircomVerifierProof(
        utxo100.hash,
        root,
      );
      const proof2 = await smtAlice.generateCircomVerifierProof(0n, root);
      const merkleProofs = [
        proof1.siblings.map((s) => s.bigInt()),
        proof2.siblings.map((s) => s.bigInt()),
      ];

      // Alice proposes the output ERC20 tokens
      const outputCommitment = newUTXO(90, Alice);

      const { nullifiers, outputCommitments, encodedProof } =
        await prepareNullifierWithdrawProof(
          Alice,
          [utxo100, ZERO_UTXO],
          [nullifier1, ZERO_UTXO],
          outputCommitment,
          root.bigInt(),
          merkleProofs,
        );

      // Alice withdraws her UTXOs to ERC20 tokens
      await expect(
        zeto
          .connect(Alice.signer)
          .withdraw(
            10,
            nullifiers,
            outputCommitments[0],
            encodeToBytesForWithdraw(root.bigInt(), encodedProof),
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
        "UTXOAlreadyOwned",
      );
    });

    it("transfer spent UTXOs should fail (double spend protection)", async function () {
      // create outputs
      const _utxo1 = newUTXO(25, Bob);
      const _utxo2 = newUTXO(5, Alice);

      // generate the nullifiers for the UTXOs to be spent
      const nullifier1 = newNullifier(utxo1, Alice);
      const nullifier2 = newNullifier(utxo2, Alice);

      // generate inclusion proofs for the UTXOs to be spent
      let root = await smtAlice.root();
      const proof1 = await smtAlice.generateCircomVerifierProof(
        utxo1.hash,
        root,
      );
      const proof2 = await smtAlice.generateCircomVerifierProof(
        utxo2.hash,
        root,
      );
      const merkleProofs = [
        proof1.siblings.map((s) => s.bigInt()),
        proof2.siblings.map((s) => s.bigInt()),
      ];

      await expect(
        doTransfer(
          Alice,
          [utxo1, utxo2],
          [nullifier1, nullifier2],
          [_utxo1, _utxo2],
          root.bigInt(),
          merkleProofs,
          [Bob, Alice],
        ),
      ).rejectedWith("UTXOAlreadySpent");
    }).timeout(600000);

    it("transfer with existing UTXOs in the output should fail (mass conservation protection)", async function () {
      // give Bob another UTXO to be able to spend
      const _utxo1 = newUTXO(15, Bob);
      await doMint(zeto, deployer, [_utxo1]);
      await smtBob.add(_utxo1.hash, _utxo1.hash);

      const nullifier1 = newNullifier(utxo7, Bob);
      const nullifier2 = newNullifier(_utxo1, Bob);
      let root = await smtBob.root();
      const proof1 = await smtBob.generateCircomVerifierProof(utxo7.hash, root);
      const proof2 = await smtBob.generateCircomVerifierProof(
        _utxo1.hash,
        root,
      );
      const merkleProofs = [
        proof1.siblings.map((s) => s.bigInt()),
        proof2.siblings.map((s) => s.bigInt()),
      ];

      await expect(
        doTransfer(
          Bob,
          [utxo7, _utxo1],
          [nullifier1, nullifier2],
          [utxo1, utxo2],
          root.bigInt(),
          merkleProofs,
          [Alice, Alice],
        ),
      ).rejectedWith("UTXOAlreadyOwned");
    }).timeout(600000);

    it("spend by using the same UTXO as both inputs should fail", async function () {
      const _utxo1 = newUTXO(20, Alice);
      const _utxo2 = newUTXO(10, Bob);
      const nullifier1 = newNullifier(utxo7, Bob);
      const nullifier2 = newNullifier(utxo7, Bob);
      // generate inclusion proofs for the UTXOs to be spent
      let root = await smtBob.root();
      const proof1 = await smtBob.generateCircomVerifierProof(utxo7.hash, root);
      const proof2 = await smtBob.generateCircomVerifierProof(utxo7.hash, root);
      const merkleProofs = [
        proof1.siblings.map((s) => s.bigInt()),
        proof2.siblings.map((s) => s.bigInt()),
      ];

      await expect(
        doTransfer(
          Bob,
          [utxo7, utxo7],
          [nullifier1, nullifier2],
          [_utxo1, _utxo2],
          root.bigInt(),
          merkleProofs,
          [Alice, Bob],
        ),
      ).rejectedWith(`UTXODuplicate`);
    }).timeout(600000);

    it("transfer non-existing UTXOs should fail", async function () {
      const nonExisting1 = newUTXO(25, Alice);
      const nonExisting2 = newUTXO(20, Alice, nonExisting1.salt);

      // add to our local SMT (but they don't exist on the chain)
      await smtAlice.add(nonExisting1.hash, nonExisting1.hash);
      await smtAlice.add(nonExisting2.hash, nonExisting2.hash);

      // generate the nullifiers for the UTXOs to be spent
      const nullifier1 = newNullifier(nonExisting1, Alice);
      const nullifier2 = newNullifier(nonExisting2, Alice);

      // generate inclusion proofs for the UTXOs to be spent
      let root = await smtAlice.root();
      const proof1 = await smtAlice.generateCircomVerifierProof(
        nonExisting1.hash,
        root,
      );
      const proof2 = await smtAlice.generateCircomVerifierProof(
        nonExisting2.hash,
        root,
      );
      const merkleProofs = [
        proof1.siblings.map((s) => s.bigInt()),
        proof2.siblings.map((s) => s.bigInt()),
      ];

      // propose the output UTXOs
      const _utxo1 = newUTXO(30, Charlie);
      utxo7 = newUTXO(15, Bob);

      await expect(
        doTransfer(
          Alice,
          [nonExisting1, nonExisting2],
          [nullifier1, nullifier2],
          [utxo7, _utxo1],
          root.bigInt(),
          merkleProofs,
          [Bob, Charlie],
        ),
      ).rejectedWith("UTXORootNotFound");
    }).timeout(600000);

    it("repeated mint calls with single UTXO should not fail", async function () {
      const utxo5 = newUTXO(10, Alice);
      await expect(doMint(zeto, deployer, [utxo5, ZERO_UTXO])).fulfilled;
      const utxo6 = newUTXO(20, Alice);
      await expect(doMint(zeto, deployer, [utxo6, ZERO_UTXO])).fulfilled;
    });
  });

  async function doTransfer(
    signer: User,
    inputs: UTXO[],
    _nullifiers: UTXO[],
    outputs: UTXO[],
    root: BigInt,
    merkleProofs: BigInt[][],
    owners: User[],
  ) {
    let nullifiers: BigNumberish[];
    let outputCommitments: BigNumberish[];
    let encryptedValues: BigNumberish[];
    let encryptionNonce: BigNumberish;
    let encodedProof: any;
    const ephemeralKeypair = genKeypair();
    const result = await prepareProof(
      signer,
      inputs,
      _nullifiers,
      outputs,
      root,
      merkleProofs,
      owners,
      ephemeralKeypair.privKey,
    );
    nullifiers = _nullifiers.map((nullifier) => nullifier.hash) as [
      BigNumberish,
      BigNumberish,
    ];
    outputCommitments = result.outputCommitments;
    encodedProof = result.encodedProof;
    encryptedValues = result.encryptedValues;
    encryptionNonce = result.encryptionNonce;

    const txResult = await sendTx(
      signer,
      nullifiers,
      outputCommitments,
      root,
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
    _nullifiers: UTXO[],
    outputs: UTXO[],
    root: BigInt,
    merkleProof: BigInt[][],
    owners: User[],
    ephemeralPrivateKey: BigInt,
  ) {
    const nullifiers = _nullifiers.map((nullifier) => nullifier.hash) as [
      BigNumberish,
      BigNumberish,
    ];
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
    let circuitToUse = circuit;
    let provingKeyToUse = provingKey;
    let isBatch = false;
    if (inputCommitments.length > 2 || outputCommitments.length > 2) {
      isBatch = true;
      circuitToUse = batchCircuit;
      provingKeyToUse = batchProvingKey;
    }
    const startWitnessCalculation = Date.now();
    const inputObj = {
      nullifiers,
      inputCommitments,
      inputValues,
      inputSalts,
      inputOwnerPrivateKey: signer.formattedPrivateKey,
      root,
      enabled: nullifiers.map((n) => (n !== 0n ? 1 : 0)),
      merkleProof,
      outputCommitments,
      outputValues,
      outputSalts: outputs.map((output) => output.salt || 0n),
      outputOwnerPublicKeys,
      ...encryptInputs,
    };
    const witness = await circuitToUse.calculateWTNSBin(inputObj, true);
    const timeWithnessCalculation = Date.now() - startWitnessCalculation;

    const startProofGeneration = Date.now();
    const { proof, publicSignals } = (await groth16.prove(
      provingKeyToUse,
      witness,
    )) as { proof: BigNumberish[]; publicSignals: BigNumberish[] };
    const timeProofGeneration = Date.now() - startProofGeneration;

    console.log(
      `Witness calculation time: ${timeWithnessCalculation}ms. Proof generation time: ${timeProofGeneration}ms.`,
    );

    // console.log(publicSignals);
    const encodedProof = encodeProof(proof);
    const encryptedValues = isBatch
      ? publicSignals.slice(2, 42)
      : publicSignals.slice(2, 10);
    return {
      inputCommitments,
      outputCommitments,
      encryptedValues,
      encryptionNonce,
      encodedProof,
    };
  }

  async function sendTx(
    signer: User,
    nullifiers: BigNumberish[],
    outputCommitments: BigNumberish[],
    root: BigNumberish,
    encryptedValues: BigNumberish[],
    encryptionNonce: BigNumberish,
    encodedProof: any,
    ecdhPublicKey: BigInt[],
  ) {
    const startTx = Date.now();
    const tx = await zeto.connect(signer.signer).transfer(
      nullifiers.filter((ic) => ic !== 0n), // trim off empty utxo hashes to check padding logic for batching works
      outputCommitments.filter((oc) => oc !== 0n), // trim off empty utxo hashes to check padding logic for batching works
      encodeToBytes(
        root,
        encryptionNonce,
        ecdhPublicKey,
        encryptedValues,
        encodedProof,
      ),
      "0x",
    );
    const results: ContractTransactionReceipt | null = await tx.wait();
    console.log(
      `Time to execute transaction: ${Date.now() - startTx}ms. Gas used: ${results?.gasUsed}`,
    );
    return results;
  }
});

function encodeToBytes(
  root: any,
  encryptionNonce: any,
  ecdhPublicKey: any,
  encryptedValues: any,
  proof: any,
) {
  return new AbiCoder().encode(
    [
      "uint256 root",
      "uint256 encryptionNonce",
      "uint256[2] ecdhPublicKey",
      "uint256[] encryptedValues",
      "tuple(uint256[2] pA, uint256[2][2] pB, uint256[2] pC)",
    ],
    [root, encryptionNonce, ecdhPublicKey, encryptedValues, proof],
  );
}
