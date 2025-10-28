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
} from "./lib/utils";
import {
  loadProvingKeys,
  prepareDepositProof,
  prepareNullifierWithdrawProof,
  encodeToBytesForDeposit,
  encodeToBytesForWithdraw,
} from "./utils";
import { deployZeto } from "./lib/deploy";
const poseidonHash = Poseidon.poseidon4;

describe("Zeto based fungible token with anonymity using nullifiers and encryption", function () {
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
  }).timeout(60000);

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

  // describe("lockStates() tests", function () {
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
