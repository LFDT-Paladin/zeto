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
  lock,
  AbiCoder,
} from "ethers";
import { expect } from "chai";
import * as chai from "chai";
chai.config.truncateThreshold = 0; // disable truncating
import { loadCircuit, Poseidon, encodeProof } from "zeto-js";
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
  inflateUtxos,
  inflateOwners,
} from "./utils";
process.env.SKIP_ANON_TESTS = "true";
import { prepareProof as prepareProofForLocked, encodeToBytes as encodeToBytesForLocked } from "./zeto_anon";
import { deployZeto } from "./lib/deploy";
import {
  Zeto_AnonNullifier,
} from "../typechain-types";

describe("Zeto based fungible token with anonymity using nullifiers without encryption", function () {
  let deployer: Signer;
  let Alice: User;
  let Bob: User;
  let Charlie: User;
  let erc20: any;
  let zeto: Zeto_AnonNullifier;
  let circuit: any, provingKey: any;
  let circuitForLocked: any, provingKeyForLocked: any;
  let batchCircuit: any, batchProvingKey: any;
  let smtAlice: Merkletree;
  let smtBob: Merkletree;

  before(async function () {
    // skip the tests if this is called by other test modules to use the exported test functions
    if (process.env.SKIP_ANON_NULLIFIER_TESTS === "true") {
      this.skip();
    }
    if (network.name !== "hardhat") {
      // accommodate for longer block times on public networks
      this.timeout(120000);
    }

    let [d, a, b, c, e] = await ethers.getSigners();
    deployer = d;
    Alice = await newUser(a);
    Bob = await newUser(b);
    Charlie = await newUser(c);

    ({ deployer, zeto, erc20 } = await deployZeto("Zeto_AnonNullifier"));

    const storage1 = new InMemoryDB(str2Bytes(""));
    smtAlice = new Merkletree(storage1, true, 64);

    const storage2 = new InMemoryDB(str2Bytes(""));
    smtBob = new Merkletree(storage2, true, 64);

    circuit = await loadCircuit("anon_nullifier_transfer");
    ({ provingKeyFile: provingKey } = loadProvingKeys(
      "anon_nullifier_transfer",
    ));
    batchCircuit = await loadCircuit("anon_nullifier_transfer_batch");
    ({ provingKeyFile: batchProvingKey } = loadProvingKeys(
      "anon_nullifier_transfer_batch",
    ));
    // for consuming locked UTXOs, we always use the "regular" circuit,
    // because the locked UTXOs are always tracked in their own base storage,
    // regardless of which token type is being used. This means for the nullifier-based token,
    // where the unlocked UTXOs are tracked in SMTs, processing unlocked UTXOs require the
    // circuits based on SMT proofs, while the locked UTXOs are processed using the "base" circuit.
    circuitForLocked = await loadCircuit("anon");
    ({ provingKeyFile: provingKeyForLocked } = loadProvingKeys(
      "anon",
    ));
  });

  beforeEach(async function () {
    // skip the tests if this is called by other test modules to use the exported test functions
    if (process.env.SKIP_ANON_NULLIFIER_TESTS === "true") {
      this.skip();
    }
  });

  it("onchain SMT root should be equal to the offchain SMT root", async function () {
    const root = await smtAlice.root();
    const onchainRoot = await zeto.getRoot();
    expect(onchainRoot).to.equal(0n);
    expect(root.string()).to.equal(onchainRoot.toString());
  });

  describe("batch transfers", () => {
    let inputUtxos: UTXO[];
    let nullifiers: UTXO[];
    let outputUtxos: UTXO[];
    let outputOwners: User[];
    let aliceUTXOsToBeWithdrawn: UTXO[];
    let txResult: any;

    beforeEach(async function () {
      this.skip();
    });

    it("mint 10 UTXOs to Alice", async function () {
      // first mint the tokens for batch testing
      inputUtxos = [];
      nullifiers = [];
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
    });

    it("Alice transfers some UTXOs to Bob and Charlie", async function () {
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
      aliceUTXOsToBeWithdrawn = [
        newUTXO(1, Alice),
        newUTXO(1, Alice),
        newUTXO(1, Alice),
      ];
      // Alice proposes the output UTXOs, 1 utxo to bob, 1 utxo to charlie and 3 utxos to alice
      const _bOut1 = newUTXO(6, Bob);
      const _bOut2 = newUTXO(1, Charlie);

      outputUtxos = [_bOut1, _bOut2, ...aliceUTXOsToBeWithdrawn];
      outputOwners = [Bob, Charlie, Alice, Alice, Alice];
      // Alice transfers her UTXOs to Bob
      txResult = await doTransfer(
        Alice,
        inputUtxos,
        nullifiers,
        outputUtxos,
        root.bigInt(),
        mtps,
        outputOwners,
      );
    });

    it("check the transfer is successful", async function () {
      const signerAddress = await Alice.signer.getAddress();
      const events = parseUTXOEvents(zeto, txResult);
      expect(events[0].submitter).to.equal(signerAddress);
      expect(events[0].inputs).to.deep.equal(nullifiers.map((n) => n.hash));

      const incomingUTXOs: any = events[0].outputs;
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
    });

    it("Alice withdraws her UTXOs to ERC20 tokens", async function () {
      // mint sufficient balance in Zeto contract address for Alice to withdraw
      const mintTx = await erc20.connect(deployer).mint(zeto, 3);
      await mintTx.wait();
      const startingBalance = await erc20.balanceOf(Alice.ethAddress);

      // Alice generates the nullifiers for the UTXOs to be spent
      const root = await smtAlice.root();
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
      const result1 = await tx.wait();
      console.log(`Method withdraw() complete. Gas used: ${result1?.gasUsed}`);

      // Alice checks her ERC20 balance
      const endingBalance = await erc20.balanceOf(Alice.ethAddress);
      expect(endingBalance - startingBalance).to.be.equal(3);
    }).timeout(60000);
  });

  describe("mint, deposit, transfer, withdraw flows", () => {
    let aliceUtxo30: UTXO;
    let aliceUtxo70: UTXO;

    beforeEach(async function () {
      this.skip();
    });

    describe("Shielding ERC20 tokens to Zeto privacy tokens", async function () {
      it("mint ERC20 tokens to Alice", async function () {
        const startingBalance = await erc20.balanceOf(Alice.ethAddress);
        const tx = await erc20.connect(deployer).mint(Alice.ethAddress, 100);
        await tx.wait();
        const endingBalance = await erc20.balanceOf(Alice.ethAddress);
        expect(endingBalance - startingBalance).to.be.equal(100);
      });

      it("Alice approves the Zeto contract to spend her ERC20 tokens, to prepare for the deposit", async function () {
        const tx1 = await erc20.connect(Alice.signer).approve(zeto.target, 100);
        await tx1.wait();
      });

      it("Alice deposits her ERC20 tokens to Zeto, and get shielded UTXOs in return", async function () {
        aliceUtxo30 = newUTXO(30, Alice);
        aliceUtxo70 = newUTXO(70, Alice);
        const { outputCommitments, encodedProof } = await prepareDepositProof(
          Alice,
          [aliceUtxo30, aliceUtxo70],
        );
        const tx2 = await zeto
          .connect(Alice.signer)
          .deposit(
            100,
            outputCommitments,
            encodeToBytesForDeposit(encodedProof),
            "0x",
          );
        const result = await tx2.wait();
        console.log(`Method deposit() complete. Gas used: ${result?.gasUsed}`);

        await smtAlice.add(aliceUtxo30.hash, aliceUtxo30.hash);
        await smtAlice.add(aliceUtxo70.hash, aliceUtxo70.hash);
        await smtBob.add(aliceUtxo30.hash, aliceUtxo30.hash);
        await smtBob.add(aliceUtxo70.hash, aliceUtxo70.hash);
      });
    });

    describe("Transferring privacy tokens", async function () {
      let value1: any;
      let salt1: bigint;
      let transferEvent: any;

      it("Check the onchain SMT root for the unlocked UTXOs should be equal to the offchain SMT root", async function () {
        const onchainRoot = await zeto.getRoot();
        const aliceRoot = await smtAlice.root();
        expect(aliceRoot.string()).to.equal(onchainRoot.toString());
        const bobRoot = await smtBob.root();
        expect(bobRoot.string()).to.equal(onchainRoot.toString());
      });

      it("Alice transfers her privacy tokens to Bob", async function () {
        // Alice proposes the output UTXOs for the transfer to Bob
        // 25 to Bob
        const _utxo1 = newUTXO(25, Bob);
        // 5 back to Alice as change
        const _utxo2 = newUTXO(5, Alice);

        // Alice will share these secrets with Bob when she performs the transfer
        value1 = _utxo1.value!;
        salt1 = _utxo1.salt!;

        // Alice generates the nullifiers for the UTXOs to be spent
        const nullifier1 = newNullifier(aliceUtxo30, Alice);

        // Alice generates inclusion proofs for the UTXOs to be spent
        const root = await smtAlice.root();
        const proof1 = await smtAlice.generateCircomVerifierProof(aliceUtxo30.hash, root);
        const proof2 = await smtAlice.generateCircomVerifierProof(0n, root);
        const merkleProofs = [
          proof1.siblings.map((s) => s.bigInt()),
          proof2.siblings.map((s) => s.bigInt()),
        ];

        // Alice transfers her UTXOs to Bob
        const result2 = await doTransfer(
          Alice,
          [aliceUtxo30, ZERO_UTXO],
          [nullifier1, ZERO_UTXO],
          [_utxo1, _utxo2],
          root.bigInt(),
          merkleProofs,
          [Bob, Alice],
        );

        // Alice locally tracks the UTXOs inside the Sparse Merkle Tree
        await smtAlice.add(_utxo1.hash, _utxo1.hash);
        await smtAlice.add(_utxo2.hash, _utxo2.hash);

        const events = parseUTXOEvents(zeto, result2);
        transferEvent = events[0];
        const signerAddress = await Alice.signer.getAddress();
        expect(transferEvent.submitter).to.equal(signerAddress);
      });

      describe("Bob can spend the tokens received from Alice", async function () {
        let bobUtxo25: UTXO;
        let transferEventToCharlie: any;

        it("Bob locally tracks the new UTXOs inside the Sparse Merkle Tree", async function () {
          // Bob parses the UTXOs from the onchain event
          // and add them to the local SMT
          await smtBob.add(transferEvent.outputs[0], transferEvent.outputs[0]);
          await smtBob.add(transferEvent.outputs[1], transferEvent.outputs[1]);

          // Bob uses the received values to construct the UTXO received from the transaction
          bobUtxo25 = newUTXO(value1, Bob, salt1);
          // Bob verifies the UTXO is valid onchain
          expect(bobUtxo25.hash).to.equal(transferEvent.outputs[0]);
        });

        it("Bob transfers UTXOs, previously received from Alice, honestly to Charlie should succeed", async function () {
          // Bob generates the nullifiers for the UTXO to be spent
          const nullifier1 = newNullifier(bobUtxo25, Bob);

          // Bob generates inclusion proofs for the UTXOs to be spent, as private input to the proof generation
          const root = await smtBob.root();
          const proof1 = await smtBob.generateCircomVerifierProof(bobUtxo25.hash, root);
          const proof2 = await smtBob.generateCircomVerifierProof(0n, root);
          const merkleProofs = [
            proof1.siblings.map((s) => s.bigInt()),
            proof2.siblings.map((s) => s.bigInt()),
          ];

          // Bob proposes the output UTXOs
          const _utxo1 = newUTXO(10, Charlie);
          const _utxo2 = newUTXO(15, Bob);

          // Bob should be able to spend the UTXO that was reconstructed from the previous transaction
          const result = await doTransfer(
            Bob,
            [bobUtxo25, ZERO_UTXO],
            [nullifier1, ZERO_UTXO],
            [_utxo1, _utxo2],
            root.bigInt(),
            merkleProofs,
            [Charlie, Bob],
          );

          // Bob keeps the local SMT in sync
          await smtBob.add(_utxo1.hash, _utxo1.hash);
          await smtBob.add(_utxo2.hash, _utxo2.hash);

          const events = parseUTXOEvents(zeto, result);
          transferEventToCharlie = events[0];
        });

        it("Alice gets the new UTXOs from the onchain event and keeps the local SMT in sync", async function () {
          await smtAlice.add(transferEventToCharlie.outputs[0], transferEventToCharlie.outputs[0]);
          await smtAlice.add(transferEventToCharlie.outputs[1], transferEventToCharlie.outputs[1]);
        });
      });
    });

    describe("Alice withdraws her UTXOs back to ERC20 tokens", async function () {
      let startingBalance: any;
      let withdrawEvent: any;

      it("Alice withdraws her UTXOs to ERC20 tokens should succeed", async function () {
        startingBalance = await erc20.balanceOf(Alice.ethAddress);

        // Alice generates the nullifiers for the UTXOs to be spent
        const nullifier1 = newNullifier(aliceUtxo70, Alice);

        // Alice generates inclusion proofs for the UTXOs to be spent
        let root = await smtAlice.root();
        const proof1 = await smtAlice.generateCircomVerifierProof(
          aliceUtxo70.hash,
          root,
        );
        const proof2 = await smtAlice.generateCircomVerifierProof(0n, root);
        const merkleProofs = [
          proof1.siblings.map((s) => s.bigInt()),
          proof2.siblings.map((s) => s.bigInt()),
        ];

        // Alice proposes the output ERC20 tokens
        const withdrawChangesUTXO = newUTXO(20, Alice);

        const { nullifiers, outputCommitments, encodedProof } =
          await prepareNullifierWithdrawProof(
            Alice,
            [aliceUtxo70, ZERO_UTXO],
            [nullifier1, ZERO_UTXO],
            withdrawChangesUTXO,
            root.bigInt(),
            merkleProofs,
          );

        // Alice withdraws her UTXOs to ERC20 tokens
        const tx = await zeto
          .connect(Alice.signer)
          .withdraw(
            50,
            nullifiers,
            outputCommitments[0],
            encodeToBytesForWithdraw(root.bigInt(), encodedProof),
            "0x",
          );
        const result = await tx.wait();
        console.log(`Method withdraw() complete. Gas used: ${result?.gasUsed}`);

        // Alice tracks the UTXO inside the SMT
        await smtAlice.add(withdrawChangesUTXO.hash, withdrawChangesUTXO.hash);
        const events = parseUTXOEvents(zeto, result);
        withdrawEvent = events[1];
      });

      it("Bob also locally tracks the new UTXOs from the withdraw event inside the SMT", async function () {
        await smtBob.add(withdrawEvent.output, withdrawEvent.output);
      });

      it("Alice checks her ERC20 balance", async function () {
        const endingBalance = await erc20.balanceOf(Alice.ethAddress);
        expect(endingBalance - startingBalance).to.be.equal(50);
      });
    });
  });

  describe("lock() tests", function () {
    beforeEach(async function () {
      // this.skip();
    });

    describe("lock -> transfer flow", function () {
      let bobUtxo1: UTXO;
      let aliceUtxo1: UTXO;
      let lockedUtxo1: UTXO;
      let lockId: string;

      before(async function () {
        // mint a UTXO for Bob
        bobUtxo1 = newUTXO(100, Bob);
        await doMint(zeto, deployer, [bobUtxo1]);
        await smtAlice.add(bobUtxo1.hash, bobUtxo1.hash);
        await smtBob.add(bobUtxo1.hash, bobUtxo1.hash);

        // mint a UTXO for Alice
        aliceUtxo1 = newUTXO(100, Alice);
        await doMint(zeto, deployer, [aliceUtxo1]);
        await smtAlice.add(aliceUtxo1.hash, aliceUtxo1.hash);
        await smtBob.add(aliceUtxo1.hash, aliceUtxo1.hash);
      });

      it("lock() should succeed when using unlocked states", async function () {
        const nullifier1 = newNullifier(bobUtxo1, Bob);
        lockedUtxo1 = newUTXO(bobUtxo1.value!, Bob);
        const root = await smtBob.root();
        const proof1 = await smtBob.generateCircomVerifierProof(
          bobUtxo1.hash,
          root,
        );
        const proof2 = await smtBob.generateCircomVerifierProof(0n, root);
        const merkleProofs = [
          proof1.siblings.map((s) => s.bigInt()),
          proof2.siblings.map((s) => s.bigInt()),
        ];
        const encodedProof = await prepareProof(
          circuit,
          provingKey,
          Bob,
          [bobUtxo1, ZERO_UTXO],
          [nullifier1, ZERO_UTXO],
          [lockedUtxo1, ZERO_UTXO],
          root.bigInt(),
          merkleProofs,
          [Bob, Bob],
        );

        const lockParameters = {
          inputs: [nullifier1.hash],
          outputs: [],
          lockedOutputs: [lockedUtxo1.hash],
        };
        const tx = await zeto.connect(Bob.signer).prepareLock(
          lockParameters,
          Alice.ethAddress, // make Alice the delegate who can spend the state (if she has the right proof)
          encodeToBytes(root.bigInt(), encodedProof), // encode the root and proof together
          "0x",
        );
        const result: ContractTransactionReceipt | null = await tx.wait();
        console.log(`Method lock() complete. Gas used: ${result?.gasUsed}`);
      });

      it("locked() should return true for locked UTXOs, and false for unlocked or spent UTXOs", async function () {
        expect(await zeto.locked(lockedUtxo1.hash)).to.deep.equal([
          true,
          Alice.ethAddress,
        ]);
        expect((await zeto.locked(aliceUtxo1.hash))[0]).to.be.false;
        expect((await zeto.locked(bobUtxo1.hash))[0]).to.be.false;
      });

      it("the current owner of the locked state can commit the lock to the delegate", async function () {
        // Bob proposes the output UTXOs, and prepares the proof for the locked state
        // to be provided to the delegate to spend the locked state
        const _utxo1 = newUTXO(10, Alice);
        const _utxo2 = newUTXO(90, Bob);

        // Alice (in reality this is usually a contract that orchestrates a trade flow) can spend the locked state
        // using the proof generated by the trade counterparty (Bob in this case)
        lockId = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        const encodedProof = await prepareProofForLocked(
          circuitForLocked,
          provingKeyForLocked,
          Bob,
          [lockedUtxo1, ZERO_UTXO],
          [_utxo1, _utxo2],
          [Alice, Bob],
          Alice.ethAddress, // current lock delegate
        );
        try {
          await
            zeto.connect(Bob.signer).commitLock(
              lockId,
              [lockedUtxo1.hash],
              Alice.ethAddress,
              { outputStates: { outputs: [_utxo1.hash, _utxo2.hash], lockedOutputs: [] }, proof: encodeToBytesForLocked(encodedProof), data: "0x" },
              { outputStates: { outputs: [], lockedOutputs: [] }, proof: "0x", data: "0x" },
              "0x",
            );
        } catch (error) {
          console.log('Error committing lock', error);
          expect.fail('Error committing lock. error: ' + error);
        }
      });

      it("the designated delegate can use the proper proof to spend the locked state", async function () {
        const tx = await zeto.connect(Alice.signer).settleLock(
          lockId,
          "0x",
        )
        const result = await tx.wait();
        const events = parseUTXOEvents(zeto, result);
        const transferLockedEvent = events[0];

        // Alice and Bob keep the local SMT in sync
        await smtAlice.add(transferLockedEvent.outputs[0], transferLockedEvent.outputs[0]);
        await smtAlice.add(transferLockedEvent.outputs[1], transferLockedEvent.outputs[1]);
        await smtBob.add(transferLockedEvent.outputs[0], transferLockedEvent.outputs[0]);
        await smtBob.add(transferLockedEvent.outputs[1], transferLockedEvent.outputs[1]);

      });

      it("onchain SMT root for the unlocked UTXOs should be equal to the offchain SMT root", async function () {
        const bobRoot = await smtBob.root();
        const aliceRoot = await smtAlice.root();
        const onchainRoot = await zeto.getRoot();
        expect(bobRoot.string()).to.equal(onchainRoot.toString());
        expect(aliceRoot.string()).to.equal(onchainRoot.toString());
      });
    });

    describe("lock -> delegate -> transfer flow", function () {
      let bobUtxo1: UTXO;
      let aliceUtxo1: UTXO;
      let lockedUtxo1: UTXO;
      let lockId: string;

      before(async function () {
        // mint a UTXO for Bob
        bobUtxo1 = newUTXO(100, Bob);
        await doMint(zeto, deployer, [bobUtxo1]);
        await smtAlice.add(bobUtxo1.hash, bobUtxo1.hash);
        await smtBob.add(bobUtxo1.hash, bobUtxo1.hash);

        // mint a UTXO for Alice
        aliceUtxo1 = newUTXO(100, Alice);
        await doMint(zeto, deployer, [aliceUtxo1]);
        await smtAlice.add(aliceUtxo1.hash, aliceUtxo1.hash);
        await smtBob.add(aliceUtxo1.hash, aliceUtxo1.hash);
      });

      it("Bob locks a UTXO and makes Alice as the delegate ", async function () {
        const nullifier1 = newNullifier(bobUtxo1, Bob);
        lockedUtxo1 = newUTXO(bobUtxo1.value!, Bob);
        const root = await smtBob.root();
        const proof1 = await smtBob.generateCircomVerifierProof(
          bobUtxo1.hash,
          root,
        );
        const proof2 = await smtBob.generateCircomVerifierProof(0n, root);
        const merkleProofs = [
          proof1.siblings.map((s) => s.bigInt()),
          proof2.siblings.map((s) => s.bigInt()),
        ];
        const encodedProof = await prepareProof(
          circuit,
          provingKey,
          Bob,
          [bobUtxo1, ZERO_UTXO],
          [nullifier1, ZERO_UTXO],
          [lockedUtxo1, ZERO_UTXO],
          root.bigInt(),
          merkleProofs,
          [Bob, Bob],
        );

        const lockParameters = {
          inputs: [nullifier1.hash],
          outputs: [],
          lockedOutputs: [lockedUtxo1.hash],
        };
        const tx = await zeto.connect(Bob.signer).prepareLock(
          lockParameters,
          Alice.ethAddress, // make Alice the delegate who can spend the state (if she has the right proof)
          encodeToBytes(root.bigInt(), encodedProof), // encode the root and proof together
          "0x",
        );
        const result: ContractTransactionReceipt | null = await tx.wait();
        console.log(`Method lock() complete. Gas used: ${result?.gasUsed}`);
      });

      it("commitLock() should succeed", async function () {
        lockId = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        const _utxo1 = newUTXO(10, Alice);
        const _utxo2 = newUTXO(90, Bob);

        const encodedProof = await prepareProofForLocked(
          circuitForLocked,
          provingKeyForLocked,
          Bob,
          [lockedUtxo1, ZERO_UTXO],
          [_utxo1, _utxo2],
          [Alice, Bob],
          Charlie.ethAddress, // expected lock delegate to settle the lock
        );
        await expect(
          zeto.connect(Alice.signer).commitLock(
            lockId,
            [lockedUtxo1.hash],
            Alice.ethAddress,
            { outputStates: { outputs: [_utxo1.hash, _utxo2.hash], lockedOutputs: [] }, proof: encodeToBytesForLocked(encodedProof), data: "0x" },
            { outputStates: { outputs: [], lockedOutputs: [] }, proof: "0x", data: "0x" },
            "0x",
          )
        ).to.be.fulfilled;
      });

      it("Alice delegates the lock to Charlie", async function () {
        const tx = await zeto
          .connect(Alice.signer)
          .delegateLock(lockId, Charlie.ethAddress, "0x");
        const result = await tx.wait();
        console.log(`Method delegateLock() complete. Gas used: ${result?.gasUsed}`);
      });

      it("Charlie can use the proper proof to spend the locked state", async function () {
        // Charlie (in reality this is usually a contract that orchestrates a trade flow) can spend the locked state
        // using the proof generated by the trade counterparty (Bob in this case)
        const tx = await zeto.connect(Charlie.signer).settleLock(
          lockId,
          "0x",
        );
        const result = await tx.wait();
        const events = parseUTXOEvents(zeto, result);
        const transferLockedEvent = events[0];

        // Alice and Bob keep the local SMT in sync
        await smtAlice.add(transferLockedEvent.outputs[0], transferLockedEvent.outputs[0]);
        await smtAlice.add(transferLockedEvent.outputs[1], transferLockedEvent.outputs[1]);
        await smtBob.add(transferLockedEvent.outputs[0], transferLockedEvent.outputs[0]);
        await smtBob.add(transferLockedEvent.outputs[1], transferLockedEvent.outputs[1]);
      });

      it("onchain SMT root for the unlocked UTXOs should be equal to the offchain SMT root", async function () {
        const bobRoot = await smtBob.root();
        const aliceRoot = await smtAlice.root();
        const onchainRoot = await zeto.getRoot();
        expect(bobRoot.string()).to.equal(onchainRoot.toString());
        expect(aliceRoot.string()).to.equal(onchainRoot.toString());
      });
    });
  });

  describe("failure cases", function () {
    // the following failure cases rely on the hardhat network
    // to return the details of the errors. This is not possible
    // on non-hardhat networks
    if (network.name !== "hardhat") {
      return;
    }

    let aliceUtxo1: UTXO;
    let aliceUtxoSpent: UTXO;

    before(async function () {
      // mint a UTXO for Alice
      aliceUtxo1 = newUTXO(100, Alice);
      aliceUtxoSpent = newUTXO(10, Alice);
      await doMint(zeto, deployer, [aliceUtxo1, aliceUtxoSpent]);
      await smtAlice.add(aliceUtxo1.hash, aliceUtxo1.hash);
      await smtAlice.add(aliceUtxoSpent.hash, aliceUtxoSpent.hash);

      // spent one of the UTXOs
      const _utxo1 = newUTXO(5, Bob);
      const _utxo2 = newUTXO(5, Alice);
      const nullifier1 = newNullifier(aliceUtxoSpent, Alice);
      const root = await smtAlice.root();
      const proof1 = await smtAlice.generateCircomVerifierProof(aliceUtxoSpent.hash, root);
      const proof2 = await smtAlice.generateCircomVerifierProof(0n, root);
      const merkleProofs = [
        proof1.siblings.map((s) => s.bigInt()),
        proof2.siblings.map((s) => s.bigInt()),
      ];
      await expect(doTransfer(
        Alice,
        [aliceUtxoSpent, ZERO_UTXO],
        [nullifier1, ZERO_UTXO],
        [_utxo1, _utxo2],
        root.bigInt(),
        merkleProofs,
        [Bob, Alice],
      )).to.be.fulfilled;

      // Alice locally tracks the UTXOs inside the Sparse Merkle Tree
      await smtAlice.add(_utxo1.hash, _utxo1.hash);
      await smtAlice.add(_utxo2.hash, _utxo2.hash);
    });

    beforeEach(async function () {
      this.skip();
    });

    it("Alice attempting to withdraw spent UTXOs should fail", async function () {
      // Alice generates the nullifiers for the UTXOs to be spent
      const nullifier1 = newNullifier(aliceUtxoSpent, Alice);

      // Alice generates inclusion proofs for the UTXOs to be spent
      let root = await smtAlice.root();
      const proof1 = await smtAlice.generateCircomVerifierProof(
        aliceUtxoSpent.hash,
        root,
      );
      const proof2 = await smtAlice.generateCircomVerifierProof(0n, root);
      const merkleProofs = [
        proof1.siblings.map((s) => s.bigInt()),
        proof2.siblings.map((s) => s.bigInt()),
      ];

      // Alice proposes the output UTXO
      const outputCommitment = newUTXO(9, Alice);

      const { encodedProof } = await prepareNullifierWithdrawProof(
        Alice,
        [aliceUtxoSpent, ZERO_UTXO],
        [nullifier1, ZERO_UTXO],
        outputCommitment,
        root.bigInt(),
        merkleProofs,
      );

      await expect(
        zeto
          .connect(Alice.signer)
          .withdraw(
            1,
            [nullifier1.hash],
            outputCommitment.hash,
            encodeToBytesForWithdraw(root.bigInt(), encodedProof),
            "0x",
          ),
      ).rejectedWith("UTXOAlreadySpent");
    });

    it("mint existing unspent UTXOs should fail", async function () {
      await expect(doMint(zeto, deployer, [aliceUtxo1])).rejectedWith(
        "UTXOAlreadyOwned",
      );
    });

    it("mint existing spent UTXOs should fail", async function () {
      await expect(doMint(zeto, deployer, [aliceUtxoSpent])).rejectedWith(
        "UTXOAlreadyOwned",
      );
    });

    it("transfer spent UTXOs should fail (double spend protection)", async function () {
      // create outputs
      const _utxo1 = newUTXO(5, Bob);
      const _utxo2 = newUTXO(5, Alice);

      // generate the nullifiers for the UTXOs to be spent
      const nullifier1 = newNullifier(aliceUtxoSpent, Alice);

      // generate inclusion proofs for the UTXOs to be spent
      let root = await smtAlice.root();
      const proof1 = await smtAlice.generateCircomVerifierProof(
        aliceUtxoSpent.hash,
        root,
      );
      const proof2 = await smtAlice.generateCircomVerifierProof(
        0n,
        root,
      );
      const merkleProofs = [
        proof1.siblings.map((s) => s.bigInt()),
        proof2.siblings.map((s) => s.bigInt()),
      ];

      await expect(
        doTransfer(
          Alice,
          [aliceUtxoSpent, ZERO_UTXO],
          [nullifier1, ZERO_UTXO],
          [_utxo1, _utxo2],
          root.bigInt(),
          merkleProofs,
          [Bob, Alice],
        ),
      ).rejectedWith("UTXOAlreadySpent");
    });

    it("transfer with existing UTXOs in the output should fail (mass conservation protection)", async function () {
      const nullifier1 = newNullifier(aliceUtxo1, Alice);
      const _utxo1 = newUTXO(90, Alice);
      let root = await smtAlice.root();
      const proof1 = await smtAlice.generateCircomVerifierProof(
        aliceUtxo1.hash,
        root,
      );
      const proof2 = await smtAlice.generateCircomVerifierProof(0n, root);
      const merkleProofs = [
        proof1.siblings.map((s) => s.bigInt()),
        proof2.siblings.map((s) => s.bigInt()),
      ];

      await expect(
        doTransfer(
          Alice,
          [aliceUtxo1, ZERO_UTXO],
          [nullifier1, ZERO_UTXO],
          [aliceUtxoSpent, _utxo1],
          root.bigInt(),
          merkleProofs,
          [Alice, Alice],
        ),
      ).rejectedWith("UTXOAlreadyOwned");
    });

    it("spend by using the same UTXO as both inputs should fail", async function () {
      const _utxo1 = newUTXO(150, Alice);
      const _utxo2 = newUTXO(50, Bob);
      const nullifier1 = newNullifier(aliceUtxo1, Alice);
      const nullifier2 = newNullifier(aliceUtxo1, Alice);
      // generate inclusion proofs for the UTXOs to be spent
      let root = await smtAlice.root();
      const proof1 = await smtAlice.generateCircomVerifierProof(
        aliceUtxo1.hash,
        root,
      );
      const proof2 = await smtAlice.generateCircomVerifierProof(
        aliceUtxo1.hash,
        root,
      );
      const merkleProofs = [
        proof1.siblings.map((s) => s.bigInt()),
        proof2.siblings.map((s) => s.bigInt()),
      ];

      await expect(
        doTransfer(
          Alice,
          [aliceUtxo1, aliceUtxo1],
          [nullifier1, nullifier2],
          [_utxo1, _utxo2],
          root.bigInt(),
          merkleProofs,
          [Alice, Bob],
        ),
      ).rejectedWith(`UTXODuplicate`);
    });

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
      const _utxo2 = newUTXO(15, Bob);

      await expect(
        doTransfer(
          Alice,
          [nonExisting1, nonExisting2],
          [nullifier1, nullifier2],
          [_utxo1, _utxo2],
          root.bigInt(),
          merkleProofs,
          [Charlie, Bob],
        ),
      ).rejectedWith("UTXORootNotFound");
    });

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
    lockDelegate?: User,
  ) {
    let nullifiers: BigNumberish[];
    let outputCommitments: BigNumberish[];
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

    const inflatedInputUtxos = inflateUtxos(inputs);
    const inflatedNullifiers = inflateUtxos(_nullifiers);
    const inflatedOutputUtxos = inflateUtxos(outputs);
    const inflatedOwners = inflateOwners(owners);

    encodedProof = await prepareProof(
      circuitToUse,
      provingKeyToUse,
      signer,
      inflatedInputUtxos,
      inflatedNullifiers,
      inflatedOutputUtxos,
      root,
      merkleProofs,
      inflatedOwners,
      lockDelegate?.ethAddress,
    );
    nullifiers = _nullifiers.map(
      (nullifier) => nullifier.hash,
    ) as BigNumberish[];
    outputCommitments = outputs.map((output) => output.hash);

    const txResult = await sendTx(
      signer,
      nullifiers,
      outputCommitments,
      root,
      encodedProof,
      lockDelegate !== undefined,
    );
    return txResult;
  }

  async function sendTx(
    signer: User,
    nullifiers: BigNumberish[],
    outputCommitments: BigNumberish[],
    root: BigNumberish,
    encodedProof: any,
    isLocked: boolean = false,
  ) {
    const startTx = Date.now();
    let tx: any;
    if (!isLocked) {
      tx = await zeto.connect(signer.signer).transfer(
        nullifiers.filter((ic) => ic !== 0n), // trim off empty utxo hashes to check padding logic for batching works
        outputCommitments.filter((oc) => oc !== 0n), // trim off empty utxo hashes to check padding logic for batching works
        encodeToBytes(root, encodedProof),
        "0x",
      );
    } else {
      tx = await zeto.connect(signer.signer).transferLocked(
        nullifiers.filter((ic) => ic !== 0n), // trim off empty utxo hashes to check padding logic for batching works
        [],
        outputCommitments.filter((oc) => oc !== 0n), // trim off empty utxo hashes to check padding logic for batching works
        encodeToBytes(root, encodedProof), // encode the root and proof together
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

  console.log(
    `Witness calculation time: ${timeWithnessCalculation}ms. Proof generation time: ${timeProofGeneration}ms.`,
  );

  const encodedProof = encodeProof(proof);
  return encodedProof;
}

function encodeToBytes(root: any, proof: any) {
  return new AbiCoder().encode(
    ["uint256 root", "tuple(uint256[2] pA, uint256[2][2] pB, uint256[2] pC)"],
    [root, proof],
  );
}

module.exports = {
  prepareProof,
  encodeToBytes,
};
