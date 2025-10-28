// Copyright © 2025 Kaleido, Inc.
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
} from "ethers";
import crypto from "crypto";
import { expect } from "chai";
import { MlKem512 } from "mlkem";
import {
  loadCircuit,
  Poseidon,
  encodeProof,
  bytesToBits,
  newEncryptionNonce,
  poseidonDecrypt,
  publicKeyFromSeed,
  recoverMlKemCiphertextBytes,
} from "zeto-js";
import testKeyPair from "zeto-js/lib/testKeypair.js";
import { groth16 } from "snarkjs";
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
} from "./lib/utils";
import {
  loadProvingKeys,
  prepareDepositProof,
  prepareNullifierWithdrawProof,
  encodeToBytesForDeposit,
  encodeToBytesForWithdraw,
} from "./utils";
import { deployZeto } from "./lib/deploy";

describe("Zeto based fungible token with anonymity using nullifiers with Kyber encryption for auditability", function () {
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
  let utxo9: UTXO;
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

    ({ deployer, zeto, erc20 } = await deployZeto(
      "Zeto_AnonNullifierQurrency",
    ));

    const storage1 = new InMemoryDB(str2Bytes(""));
    smtAlice = new Merkletree(storage1, true, 64);

    const storage2 = new InMemoryDB(str2Bytes(""));
    smtBob = new Merkletree(storage2, true, 64);

    circuit = await loadCircuit("anon_nullifier_qurrency_transfer");
    ({ provingKeyFile: provingKey } = loadProvingKeys(
      "anon_nullifier_qurrency_transfer",
    ));
    batchCircuit = await loadCircuit("anon_nullifier_qurrency_transfer_batch");
    ({ provingKeyFile: batchProvingKey } = loadProvingKeys(
      "anon_nullifier_qurrency_transfer_batch",
    ));
  });

  describe("batch transfer", function () {
    it("onchain SMT root should be equal to the offchain SMT root", async function () {
      const root = await smtAlice.root();
      const onchainRoot = await zeto.getRoot();
      expect(onchainRoot).to.equal(0n);
      expect(root.string()).to.equal(onchainRoot.toString());
    });

    it("(batch) mint to Alice and batch transfer 10 UTXOs honestly to Bob & Charlie then withdraw should succeed", async function () {
      this.timeout(600000);

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
      // check the non-empty output hashes are correct
      for (let i = 0; i < outputUtxos.length; i++) {
        // Bob uses the information received from Alice to reconstruct the UTXO sent to him
        const receivedValue = outputUtxos[i].value;
        const receivedSalt = outputUtxos[i].salt;
        const hash = Poseidon.poseidon4([
          BigInt(receivedValue),
          receivedSalt,
          outputOwners[i].babyJubPublicKey[0],
          outputOwners[i].babyJubPublicKey[1],
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
    }).timeout(60000);
  });

  describe("transfer with verifications by the receiver and the audit authority", function () {
    let event: any;
    let outputUTXOs: UTXO[];
    let outputOwners: User[];

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
        [utxo0, utxo100],
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

      // Alice transfers her UTXOs to Bob
      outputUTXOs = [_utxo3, utxo4];
      outputOwners = [Bob, Alice];
      const result2 = await doTransfer(
        Alice,
        [utxo1, utxo2],
        [nullifier1, nullifier2],
        outputUTXOs,
        root.bigInt(),
        merkleProofs,
        outputOwners,
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
      event = events[0];
      expect(event.submitter).to.equal(signerAddress);
      expect(event.inputs).to.deep.equal([nullifier1.hash, nullifier2.hash]);
      expect(event.outputs).to.deep.equal([_utxo3.hash, utxo4.hash]);
      await smtBob.add(event.outputs[0], event.outputs[0]);
      await smtBob.add(event.outputs[1], event.outputs[1]);

      // Bob uses the information received from Alice to reconstruct the UTXO sent to him
      const receivedValue = _utxo3.value!;
      const receivedSalt = _utxo3.salt;
      const incomingUTXOs: any = event.outputs;
      const hash = Poseidon.poseidon4([
        BigInt(receivedValue),
        receivedSalt,
        Bob.babyJubPublicKey[0],
        Bob.babyJubPublicKey[1],
      ]);
      expect(incomingUTXOs[0]).to.equal(hash);

      // Bob uses the decrypted values to construct the UTXO received from the transaction
      utxo3 = newUTXO(receivedValue, Bob, receivedSalt);
    }).timeout(600000);

    it("The audit authority can decrypt the encrypted values in the transfer event", async function () {
      // The audit authority can decrypt the encrypted values in the transfer event
      const encapsulatedSharedSecret = event.encapsulatedSharedSecret;
      const cBytes = recoverMlKemCiphertextBytes(encapsulatedSharedSecret);
      // the receiver can decap the ciphertext, and recover the shared secret
      // using the mlkem ciphertext and the receiver's private key
      const receiver = new MlKem512();
      const ssReceiver = await receiver.decap(
        new Uint8Array(cBytes),
        new Uint8Array(testKeyPair.sk),
      );
      // corresponding to the logic in the circuit "pubkey.circom", we derive the symmetric key
      // from the shared secret
      expect(ssReceiver.length).to.equal(32);
      const recoveredKey = publicKeyFromSeed(ssReceiver);

      const encryptedValues = event.encryptedValues;
      const encryptionNonce = event.encryptionNonce;
      expect(encryptedValues.length).to.equal(16);

      let plainText = poseidonDecrypt(
        encryptedValues,
        recoveredKey,
        encryptionNonce,
        14,
      );
      expect(plainText[0]).to.equal(Alice.babyJubPublicKey[0]);
      expect(plainText[1]).to.equal(Alice.babyJubPublicKey[1]);
      expect(plainText[2]).to.equal(BigInt(utxo1.value!));
      expect(plainText[3]).to.equal(utxo1.salt!);
    });
  });

  // describe("lock() tests", function () {
  //   let lockedUtxo1: UTXO;
  //   let smtBobForLocked: Merkletree;
  //   let utxo10: UTXO;
  //   let utxo11: UTXO;
  //   let utxo12: UTXO;

  //   before(async function () {
  //     const storage1 = new InMemoryDB(str2Bytes(""));
  //     smtBobForLocked = new Merkletree(storage1, true, 64);

  //     // mint a UTXO for Bob and spend it (to use it in a failure case test)
  //     utxo12 = newUTXO(1, Alice);
  //     await doMint(zeto, deployer, [utxo12]);
  //     await smtAlice.add(utxo12.hash, utxo12.hash);
  //     await smtBob.add(utxo12.hash, utxo12.hash);

  //     const _utxo1 = newUTXO(1, Bob);
  //     const nullifier1 = newNullifier(utxo12, Alice);
  //     let root = await smtAlice.root();
  //     const proof1 = await smtAlice.generateCircomVerifierProof(utxo12.hash, root);
  //     const proof2 = await smtAlice.generateCircomVerifierProof(utxo12.hash, root);
  //     const merkleProofs = [
  //       proof1.siblings.map((s) => s.bigInt()),
  //       proof2.siblings.map((s) => s.bigInt()),
  //     ];

  //     await doTransfer(
  //       Alice,
  //       [utxo12, ZERO_UTXO],
  //       [nullifier1, ZERO_UTXO],
  //       [_utxo1, ZERO_UTXO],
  //       root.bigInt(),
  //       merkleProofs,
  //       [Bob, Alice],
  //     );
  //     await smtAlice.add(_utxo1.hash, _utxo1.hash);
  //     await smtBob.add(_utxo1.hash, _utxo1.hash);
  //   });

  //   describe("lock -> transfer flow", function () {
  //     it("lock() should succeed when using unlocked states", async function () {
  //       const nullifier1 = newNullifier(utxo7, Bob);
  //       lockedUtxo1 = newUTXO(utxo7.value!, Bob);
  //       const root = await smtBob.root();
  //       const proof1 = await smtBob.generateCircomVerifierProof(
  //         utxo7.hash,
  //         root,
  //       );
  //       const proof2 = await smtBob.generateCircomVerifierProof(0n, root);
  //       const merkleProofs = [
  //         proof1.siblings.map((s) => s.bigInt()),
  //         proof2.siblings.map((s) => s.bigInt()),
  //       ];
  //       const { outputCommitments, encodedProof } = await prepareProof(
  //         circuit,
  //         provingKey,
  //         Bob,
  //         [utxo7, ZERO_UTXO],
  //         [nullifier1, ZERO_UTXO],
  //         [lockedUtxo1, ZERO_UTXO],
  //         root.bigInt(),
  //         merkleProofs,
  //         [Bob, Bob],
  //       );

  //       const tx = await zeto.connect(Bob.signer).lock(
  //         [nullifier1.hash],
  //         [],
  //         outputCommitments,
  //         root.bigInt(),
  //         encodedProof,
  //         Alice.ethAddress, // make Alice the delegate who can spend the state (if she has the right proof)
  //         "0x",
  //       );
  //       const result: ContractTransactionReceipt | null = await tx.wait();

  //       // Note that the locked UTXO should NOT be added to the local SMT for UTXOs because it's tracked in a separate SMT onchain
  //       // we add it to the local SMT for locked UTXOs
  //       const events = parseUTXOEvents(zeto, result!);
  //       await smtBobForLocked.add(
  //         events[0].lockedOutputs[0],
  //         ethers.toBigInt(events[0].delegate),
  //       );
  //     });

  //     it("onchain SMT root for the locked UTXOs should be equal to the offchain SMT root", async function () {
  //       const root = await smtBobForLocked.root();
  //       const onchainRoot = await zeto.getRootForLocked();
  //       expect(root.string()).to.equal(onchainRoot.toString());
  //     });

  //     it("the designated delegate can use the proper proof to spend the locked state", async function () {
  //       // Bob generates inclusion proofs for the UTXOs to be spent, as private input to the proof generation
  //       const nullifier1 = newNullifier(lockedUtxo1, Bob);
  //       const root = await smtBobForLocked.root();
  //       const proof1 = await smtBobForLocked.generateCircomVerifierProof(
  //         lockedUtxo1.hash,
  //         root,
  //       );
  //       const proof2 = await smtBobForLocked.generateCircomVerifierProof(
  //         0n,
  //         root,
  //       );
  //       const merkleProofs = [
  //         proof1.siblings.map((s) => s.bigInt()),
  //         proof2.siblings.map((s) => s.bigInt()),
  //       ];
  //       // Bob proposes the output UTXOs, attempting to transfer the locked UTXO to Alice
  //       utxo9 = newUTXO(10, Alice);
  //       utxo10 = newUTXO(5, Bob);

  //       const result = await prepareProof(
  //         circuitForLocked,
  //         provingKeyForLocked,
  //         Bob,
  //         [lockedUtxo1, ZERO_UTXO],
  //         [nullifier1, ZERO_UTXO],
  //         [utxo9, utxo10],
  //         root.bigInt(),
  //         merkleProofs,
  //         [Alice, Bob],
  //         Alice.ethAddress, // current lock delegate
  //       );
  //       const nullifiers = [nullifier1.hash];

  //       // Alice (in reality this is usually a contract that orchestrates a trade flow) can spend the locked state
  //       // using the proof generated by the trade counterparty (Bob in this case)
  //       await expect(
  //         sendTx(
  //           Alice,
  //           nullifiers,
  //           result.outputCommitments,
  //           root.bigInt(),
  //           result.encodedProof,
  //           true,
  //         ),
  //       ).to.be.fulfilled;

  //       // Alice and Bob keep the local SMT in sync
  //       await smtAlice.add(utxo9.hash, utxo9.hash);
  //       await smtAlice.add(utxo10.hash, utxo10.hash);
  //       await smtBob.add(utxo9.hash, utxo9.hash);
  //       await smtBob.add(utxo10.hash, utxo10.hash);
  //     });

  //     it("onchain SMT root for the locked UTXOs should be equal to the offchain SMT root", async function () {
  //       const root = await smtBobForLocked.root();
  //       const onchainRoot = await zeto.getRootForLocked();
  //       expect(root.string()).to.equal(onchainRoot.toString());
  //     });

  //     it("onchain SMT root for the unlocked UTXOs should be equal to the offchain SMT root", async function () {
  //       const root = await smtBob.root();
  //       const onchainRoot = await zeto.getRoot();
  //       expect(root.string()).to.equal(onchainRoot.toString());
  //     });
  //   });
  // });

  async function doTransfer(
    signer: User,
    inputs: UTXO[],
    _nullifiers: UTXO[],
    outputs: UTXO[],
    root: BigInt,
    merkleProofs: BigInt[][],
    owners: User[],
    lockDelegate?: User,
  ) {
    let nullifiers: BigNumberish[];
    let outputCommitments: BigNumberish[];
    let encryptionNonce: BigNumberish;
    let outputsCiphertext: BigNumberish[];
    let encapsulatedSharedSecret: BigNumberish[];
    let encodedProof: any;
    const circuitToUse = lockDelegate
      ? circuitForLocked
      : inputs.length > 2
        ? batchCircuit
        : circuit;
    const provingKeyToUse = lockDelegate
      ? provingKeyForLocked
      : inputs.length > 2
        ? batchProvingKey
        : provingKey;
    const result = await prepareProof(
      circuitToUse,
      provingKeyToUse,
      signer,
      inputs,
      _nullifiers,
      outputs,
      root,
      merkleProofs,
      owners,
      lockDelegate?.ethAddress,
    );
    nullifiers = _nullifiers.map(
      (nullifier) => nullifier.hash,
    ) as BigNumberish[];
    outputCommitments = result.outputCommitments;
    encodedProof = result.encodedProof;
    encryptionNonce = result.encryptionNonce;
    outputsCiphertext = result.outputsCiphertext;
    encapsulatedSharedSecret = result.encapsulatedSharedSecret;

    const txResult = await sendTx(
      signer,
      nullifiers,
      outputCommitments,
      root,
      encryptionNonce,
      outputsCiphertext,
      encapsulatedSharedSecret,
      encodedProof,
      lockDelegate !== undefined,
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

  async function sendTx(
    signer: User,
    nullifiers: BigNumberish[],
    outputCommitments: BigNumberish[],
    root: BigNumberish,
    encryptionNonce: BigNumberish,
    outputsCiphertext: BigNumberish[],
    encapsulatedSharedSecret: BigNumberish[],
    encodedProof: any,
    isLocked: boolean = false,
  ) {
    const startTx = Date.now();
    let tx: any;
    const proof = encodeToBytes(
      root,
      encryptionNonce,
      outputsCiphertext,
      encapsulatedSharedSecret,
      encodedProof,
    );
    if (!isLocked) {
      tx = await zeto.connect(signer.signer).transfer(
        nullifiers.filter((ic) => ic !== 0n), // trim off empty utxo hashes to check padding logic for batching works
        outputCommitments.filter((oc) => oc !== 0n), // trim off empty utxo hashes to check padding logic for batching works
        proof,
        "0x",
      );
    } else {
      tx = await zeto.connect(signer.signer).transferLocked(
        nullifiers.filter((ic) => ic !== 0n), // trim off empty utxo hashes to check padding logic for batching works
        [],
        outputCommitments.filter((oc) => oc !== 0n), // trim off empty utxo hashes to check padding logic for batching works
        proof,
        "0x",
      );
    }
    const results: ContractTransactionReceipt | null = await tx.wait();
    console.log(
      `Time to execute transaction: ${Date.now() - startTx}ms. Gas used: ${results?.gasUsed}`,
    );
    return results;
  }
});

async function prepareProof(
  circuit: any,
  provingKey: any,
  signer: User,
  inputs: UTXO[],
  _nullifiers: UTXO[],
  outputs: UTXO[],
  root: BigInt,
  merkleProof: BigInt[][],
  owners: User[],
  lockDelegate?: string,
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

  const randomness = crypto.randomBytes(32);
  const r = bytesToBits(randomness);
  const encryptionNonce = newEncryptionNonce();
  const startWitnessCalculation = Date.now();
  const inputObj: any = {
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
    randomness: r,
    encryptionNonce,
  };
  if (lockDelegate) {
    inputObj["lockDelegate"] = ethers.toBigInt(lockDelegate);
  }

  const witness = await circuit.calculateWTNSBin(inputObj, true);
  const timeWithnessCalculation = Date.now() - startWitnessCalculation;

  const startProofGeneration = Date.now();
  const { proof, publicSignals } = (await groth16.prove(
    provingKey,
    witness,
  )) as { proof: BigNumberish[]; publicSignals: BigNumberish[] };
  const timeProofGeneration = Date.now() - startProofGeneration;

  const length = outputCommitments.length > 2 ? 64 : 16;
  const encapsulatedSharedSecret = publicSignals.slice(0, 25);
  const outputsCiphertext = publicSignals.slice(25, 25 + length);

  console.log(
    `Witness calculation time: ${timeWithnessCalculation}ms. Proof generation time: ${timeProofGeneration}ms.`,
  );

  const encodedProof = encodeProof(proof);
  return {
    inputCommitments,
    outputCommitments,
    encodedProof,
    encryptionNonce,
    outputsCiphertext,
    encapsulatedSharedSecret,
  };
}

function encodeToBytes(
  root: any,
  encryptionNonce: any,
  encryptedValues: any,
  encapsulatedSharedSecret: any,
  proof: any,
) {
  return new AbiCoder().encode(
    [
      "uint256 root",
      "uint256 encryptionNonce",
      "uint256[] encryptedValues",
      "uint256[25] encapsulatedSharedSecret",
      "tuple(uint256[2] pA, uint256[2][2] pB, uint256[2] pC)",
    ],
    [root, encryptionNonce, encryptedValues, encapsulatedSharedSecret, proof],
  );
}

module.exports = {
  prepareProof,
};

describe("encoding test", function () {
  it("should encode the proof correctly", function () {
    const proof = encodeToBytes(
      2185945469173281998543795100239332646380217964035682609677494700854501229435n, // root
      275390031262136596949503856056006740272n, // encryptionNonce
      [
        13715591515004609688233255520139366968347229879226987447392926581641315410365n,
        12225040792969183937477801836359093706337068545022080407734986798228486880459n,
        13011843324002630531326495134664720300521666217887617808427836215465667928692n,
        19856495997717871827317781271670963924363352390548953270211310380014460390334n,
        10604073410745110687091665574819448938663378994798073962869528739665232014421n,
        4435178295556424656324960575659262079598790982598728711009699368000570989336n,
        4933836950213445512336611933470005675174051517599168194217630597808234407822n,
        4214225226975003066728797596550538286539095487779015468026667054118086708667n,
        5024576208387901066062709265269626900637589025955141460411534463069531901891n,
        703973997727387811759298044568434494690485054474094541129706149430879630884n,
        14507146421329688672993934183526210401463938041762433569084930573959882425326n,
        14012438595855534325416420918184230363976318221634661889145359708752658755207n,
        8754932719802650626162524741856226517982355523480941833310179558554675571452n,
        14352194087842591409364852158942330879045556303811584255462682741598400114507n,
        930427648599696993608342770250501205956137552217414712238549287557300544904n,
        21394278059543057034208592185307596281934697437416095108050934185203559222712n,
      ], // encryptedValues
      [
        288126790059318346139824202713129652229348576996464001952408714015513463993n,
        237407267603824073552608687931930991963999394428366555167539009382905388537n,
        114764209448275499414271899760871155095571139138912032913196740291197144696n,
        436995396164250682578369063006271991698559693192849862783563046924655949369n,
        240591981726723986881909418996515793567853950883197759098846148099856667367n,
        423589442784611103138623838389086946618384967919367390938087104637737788216n,
        145462886897996314213326681029317456734837820615410128121849599895343382705n,
        389932051522827200062535000655062077695415252609124727680940113692289747665n,
        243675801576408693743852761736871686197324939358886873348705983761231779940n,
        87939610206601698004485673787337315272887533489281795861381157598783844367n,
        11014683993036861793302780310552914749438060162054842543618251146378375526n,
        111614391393324468932660651857272851218377641294817341376507043259517434344n,
        435707583091444288657484999813927778656294844261499799508340404768617948216n,
        256449006844324353610179235842731870600460006591548128221647489805788554815n,
        418634767833052917835192672729088145298440004524459401783387363547257320986n,
        103610780261386527074710704895000705809005120944489697847370877795317539063n,
        127627753495450202619315508879418050934338498775659516820680842878935424334n,
        46384251041970312953604802331459565502839961155990167432349041542488773332n,
        59279347778101058820051248467497773070279609242238499827597758128700405210n,
        401076038589967842843270755588760950994197089793842470053926063226777655114n,
        437055888722697362599388401811652409455332242376917929776279980055423605099n,
        382219076120208743166804616016001837790918283786525158013655719261656086690n,
        412218952494890119014684951992443508961594053505588316664570435208291787650n,
        362621741079924474296483570929701950283961620929630348838376271651154374200n,
        3987927141671093050828825554766656132900595007161822411291n,
      ], // encapsulatedSharedSecret
      [
        [
          549287572509790359685716132453355766491815426087194122700979105235739473130n,
          15298123219329538989607681043913355391761570794419278588736377843648111671159n,
        ],
        [
          [
            9440038941921968905445133266072988463231863413680655261260818687531566458108n,
            2207698080461885696867541047133088519732009024182544199097906381032204346428n,
          ],
          [
            6577776031418234473059205922833530313720519798861738979049253341371055729708n,
            11968330310582097325419116485228879165470205732203147205908830680466052312773n,
          ],
        ],
        [
          3106716200655790292773114695208727957822992667898408535199502363885960505738n,
          20085498771862832325662320796990160779029948991590746485323346020588480720567n,
        ],
      ], // proof
    );
    expect(proof).to.equal(
      "0x04d53387cb12538667ced7ce8b1846dbdff33fc38784b2604a08125446b4c37b00000000000000000000000000000000cf2e30d59acb9763a0c1626c5e6a0930000000000000000000000000000000000000000000000000000000000000048000a312f09e6066c7aebc7468b5cf1aafa3151c298175dbd658d5acba17e74cb900865e24f8de2a91bdfaaaa40792466eab7b9767f8e8fa1903b80825f3c99df90040f4491d9acb71301b8f394d01b5920669cedd5af8da172226d505d1740e7800f754a41cdcdf6a81a97771a25a885d09c64b8464f53d4b0e0292c8aa9a763900882b9495929d332f40dde4a0ff1b9e162cc2f802a603faabcff12074fc12e700efbe3daa599448fdc6c90e7919ba04a86b0c6accdb304e9f325aafc1ce63380052543e5908a1d6165f2f82e3136c2c95e9e185e2aec7ddf95139401b6ac0b100dcb197a37a65273cf5115a71ab6e24e0a67227303dd03600e34b46d3694ad10089ea65d1df01235226c5985d0e8853f7ba53d641a12948e5a98141aafa18640031c5a56e40a3988cde8b4a2d3baa8a42813226e602951754c3668f8627b00f00063bed560dd4187b7a6ad7e31858dbbf2cf8583c7e1a883124098067387166003f2be7dee087211d4ad509d7385c4cd293052ab7050d6e0ecb224d604af9e800f69a0c789609111b4e125f60324eeb682ee8216ffc19ffec929a77bc2264380091251e55d2b6b1e3b64f803ffac769bba390eee196c95dd718e7d0cb0aa63f00ecf05a8eb06e090213be5b5fd338dbacfc6d18d835dfa7719d763a47b1361a003aa4416f29bc3291dae5fa6dd98e44dc40beef68c6b15e21fb1b15cb7760f700483c187b8e203bf7433a3316ccc9aad2fdcd6aafbb328bf79bf7a2ec9cdd4e001a40a77e1af8c8ac79aa167d1c519a097c76158230b125b9ddd2830905d2d400218d0936c05cae6f1f92d1b5ac105573fd70b2a5f3cb0ac4a0bc6fcab635da00e3004117a1cb79135f18f5de7019a2828ee3f41b1f2b5adf57e891fb16574a00f75d67e80cb479cf92b2ad3c521830c41d1721130d801f6b58f4ffc277d96b00d8540d7b056af7eec2368efb244c68fb684803562bbd14321c2274e33878a200e94ec2bd8059bda202a769b7312c5c194e418cc0eb9b0a27e56fbc627ba38200cd3c93ec8281b7fad9dd5183dd892f98b9b7beae868eb6f8f17d806af32e380000000000000000a2a3e6ee40deb77d25dc4473312ff54bc727758efd4cfa1b0136e2c06cabb082011e47ab176222198f0fa0885e8046650f31aeab65a9f4ea21d26e4f641fe77a3cb7215d4b3c9cec9a1f7148edc75c6b2b9390636f55777714dedf690fa175f2f4a8f9298cead433608482fa3251c9c4df1be18156bf64fc04e18348fd35af148608f6dfccdf42139dd1278a947b119993784074aaf5243c0e8ae3a922c4523d0207bd28e658e37add64feeefcadfcd4feae9b93ceb3ec2c1a75d5bc03c3417b3db41c75a87b563433c27d11efd64439837b0994fcb76ec506de56cc662d32548f11121f83941d43b37a6bdce0c5edf070969dc971c5298a2c67fd4bd7994866b73163e4136ee3d0f6662a529f73c569f8dd606ae7a96eb700000000000000000000000000000000000000000000000000000000000000101e52bfec13e500dee652a10feec8bd596cd62472ad5430ff9b4f3c944780e1bd1b0720bd0450e3d549636d5f23142b50b485f4f4c17323a7809dcf5a1309fccb1cc4713ce4478327e0e5be00dab93879dd260a0d8e2f8f2f905b209d189f22742be660e2dbbd0509b1da03413b66d393cbf348cf51fc2b0fdf7ebf08c876cbbe1771b15f2cbd88f6be76a81e83c776e188643bbafb6dedf729d0ccb0f9842c5509ce38d221fac0e2d5b3ecb54fbdaa45f47a74ed36962b8e882210b132331b180ae873e79f48e142c4ce247a664f22bb5a05872d7c56e5fdb7566f7eecf7a78e09512abd52a1902b33ffdeb72f0fd9b957e52d7b4a30604c47e32471ce2d0dbb0b1bcf31c47aef99da156d515d7b0a7ed4f898bb3580b71f8284de17a70f8fc3018e6f66d2ac7be681123be5cf9f29bdc218250aea1fa2cc20c8905b8170b6242012c0ff596494029442db4331e3e715487b650b39c4342c0c0b34a4eb7543ee1efac25a423edb6db7187e692f0c7d3edd5753d359edd2f35e72ffa4d716ee87135b1dc6ee74854c498020893eeea7047c3dadaf2ff08196f557bdee8289eafc1fbb0dd1dd670fec48828f7aa41bcde200551317cfc3132cdb4e1682a5dd6f4b020e9a7791ce7135d2d847313b73c26cb48ca320f164b12826752d175668e5882f4cbb75ae037a782db136d5e3588575122a44f059298c7148f1482fd89acdb8",
    );
  });
});
