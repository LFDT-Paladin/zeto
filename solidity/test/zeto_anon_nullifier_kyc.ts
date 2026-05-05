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
import { loadCircuit, Poseidon, encodeProof, kycHash } from "zeto-js";
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
  parseRegistryEvents,
  logger,
} from "./lib/utils";
import {
  loadProvingKeys,
  prepareDepositKycProof,
  prepareNullifierWithdrawProof,
  encodeToBytesForDeposit,
  encodeToBytesForWithdraw,
  calculateSpendHash,
  calculateCancelHash,
} from "./utils";
import { deployZeto } from "./lib/deploy";
import smt from "../ignition/modules/test/smt";

if (!process.env.CIRCUITS_ROOT) {
  process.env.CIRCUITS_ROOT = "/Users/jimzhang/Documents/zkp/circuits/";
}
if (!process.env.PROVING_KEYS_ROOT) {
  process.env.PROVING_KEYS_ROOT = "/Users/jimzhang/Documents/zkp/proving-keys/";
}

// ABI fragments for the ZetoLockableCapability *Args payloads. These mirror
// the Solidity structs declared in IZetoLockableCapability.sol and let the
// tests construct the opaque `bytes` parameters that the lock lifecycle
// methods (createLock / updateLock / delegateLock / spendLock / cancelLock)
// pass through to the token-specific encoders.
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

// The unlocked-input path encodes (root, ZkProof) so the contract can
// validate the SMT root before delegating to the verifier. The locked-input
// path elides the root: locked UTXOs are tracked in a flat per-lock mapping
// rather than an SMT, so there's no Merkle root to assert membership against.
function encodeUnlockedProof(root: BigNumberish, proof: any) {
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

describe("Zeto based fungible token with anonymity, KYC, using nullifiers without encryption", function () {
  let deployer: Signer;
  let Alice: User;
  let Bob: User;
  let Charlie: User;
  let unregistered: User;
  let erc20: any;
  let zeto: any;
  let utxo100: UTXO;
  let utxo0: UTXO;
  let utxo1: UTXO;
  let utxo2: UTXO;
  let utxo3: UTXO;
  let _utxo3: UTXO;
  let utxo4: UTXO;
  let utxo6: UTXO;
  let utxo7: UTXO;
  let withdrawChangeUTXO: UTXO;
  let circuit: any, provingKey: any;
  let batchCircuit: any, batchProvingKey: any;
  let circuitForLocked: any, provingKeyForLocked: any;
  let smtAlice: Merkletree;
  let smtBob: Merkletree;
  let smtKyc: Merkletree;
  let smtUnregistered: Merkletree;

  before(async function () {
    if (network.name !== "hardhat") {
      // accommodate for longer block times on public networks
      this.timeout(120000);
    }
    let [d, a, b, c, e] = await ethers.getSigners();
    deployer = d;
    Alice = await newUser(a);
    Bob = await newUser(b);
    Charlie = await newUser(c);
    unregistered = await newUser(e);

    ({ deployer, zeto, erc20 } = await deployZeto("Zeto_AnonNullifierKyc"));

    const tx2 = await zeto
      .connect(deployer)
      .register(Alice.babyJubPublicKey, "0x");
    const result1 = await tx2.wait();
    const tx3 = await zeto
      .connect(deployer)
      .register(Bob.babyJubPublicKey, "0x");
    const result2 = await tx3.wait();
    const tx4 = await zeto
      .connect(deployer)
      .register(Charlie.babyJubPublicKey, "0x");
    const result3 = await tx4.wait();

    const storage1 = new InMemoryDB(str2Bytes("alice"));
    smtAlice = new Merkletree(storage1, true, 64);

    const storage2 = new InMemoryDB(str2Bytes("bob"));
    smtBob = new Merkletree(storage2, true, 64);

    const storage3 = new InMemoryDB(str2Bytes("kyc"));
    smtKyc = new Merkletree(storage3, true, 10);

    const storage4 = new InMemoryDB(str2Bytes("unregistered"));
    smtUnregistered = new Merkletree(storage4, true, 64);

    const publicKey1 = parseRegistryEvents(zeto, result1);
    await smtKyc.add(kycHash(publicKey1), kycHash(publicKey1));
    const publicKey2 = parseRegistryEvents(zeto, result2);
    await smtKyc.add(kycHash(publicKey2), kycHash(publicKey2));
    const publicKey3 = parseRegistryEvents(zeto, result3);
    await smtKyc.add(kycHash(publicKey3), kycHash(publicKey3));

    circuit = await loadCircuit("anon_nullifier_kyc_transfer");
    ({ provingKeyFile: provingKey } = loadProvingKeys(
      "anon_nullifier_kyc_transfer",
    ));
    batchCircuit = await loadCircuit("anon_nullifier_kyc_transfer_batch");
    ({ provingKeyFile: batchProvingKey } = loadProvingKeys(
      "anon_nullifier_kyc_transfer_batch",
    ));
    circuitForLocked = await loadCircuit("anon_nullifier_kyc_transferLocked");
    ({ provingKeyFile: provingKeyForLocked } = loadProvingKeys(
      "anon_nullifier_kyc_transferLocked",
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
        await smtUnregistered.add(mintedHashes[i], mintedHashes[i]);
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

    // Alice generates inclusion proofs for the identities in the transaction
    const identitiesRoot = await smtKyc.root();
    const aProof = await smtKyc.generateCircomVerifierProof(
      kycHash(Alice.babyJubPublicKey),
      identitiesRoot,
    );
    const aliceProof = aProof.siblings.map((s) => s.bigInt());
    const bProof = await smtKyc.generateCircomVerifierProof(
      kycHash(Bob.babyJubPublicKey),
      identitiesRoot,
    );
    const bobProof = bProof.siblings.map((s) => s.bigInt());

    const cProof = await smtKyc.generateCircomVerifierProof(
      kycHash(Charlie.babyJubPublicKey),
      identitiesRoot,
    );
    const charlieProof = cProof.siblings.map((s) => s.bigInt());
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
    const identityMerkleProofs = [
      aliceProof,
      bobProof,
      charlieProof,
      aliceProof,
      aliceProof,
      aliceProof,
    ];
    const inflatedOutputUtxos = [...outputUtxos];
    const inflatedOutputOwners = [...outputOwners];
    for (let i = 0; i < 10 - outputUtxos.length; i++) {
      inflatedOutputUtxos.push(ZERO_UTXO);
      inflatedOutputOwners.push(Bob);
      identityMerkleProofs.push(bobProof);
    }

    // Alice transfers her UTXOs to Bob
    const result = await doTransfer(
      Alice,
      inputUtxos,
      nullifiers,
      inflatedOutputUtxos,
      root.bigInt(),
      mtps,
      identitiesRoot.bigInt(),
      identityMerkleProofs,
      inflatedOutputOwners,
    );

    const signerAddress = await Alice.signer.getAddress();
    const events = parseUTXOEvents(zeto, result.txResult!);
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
      await smtUnregistered.add(incomingUTXOs[i], incomingUTXOs[i]);
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
    utxo0 = newUTXO(0, Alice);
    const identitiesRoot = await smtKyc.root();
    const proof3 = await smtKyc.generateCircomVerifierProof(
      kycHash(Alice.babyJubPublicKey),
      identitiesRoot,
    );
    const identitiesMerkleProofs = [
      proof3.siblings.map((s) => s.bigInt()),
      proof3.siblings.map((s) => s.bigInt()),
    ];
    const { outputCommitments, encodedProof } = await prepareDepositKycProof(
      Alice,
      [utxo100, utxo0],
      identitiesRoot.bigInt(),
      identitiesMerkleProofs,
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
    let utxosRoot = await smtAlice.root();
    let onchainRoot = await zeto.getRoot();
    expect(utxosRoot.string()).to.equal(onchainRoot.toString());
    // Bob also locally tracks the UTXOs inside the Sparse Merkle Tree
    await smtBob.add(_utxo1, _utxo1);
    await smtBob.add(_utxo2, _utxo2);

    // Alice proposes the output UTXOs for the transfer to Bob
    _utxo3 = newUTXO(25, Bob);
    utxo4 = newUTXO(5, Alice);

    // Alice generates the nullifiers for the UTXOs to be spent
    const nullifier1 = newNullifier(utxo1, Alice);
    const nullifier2 = newNullifier(utxo2, Alice);

    // Alice generates inclusion proofs for the UTXOs to be spent
    const proof1 = await smtAlice.generateCircomVerifierProof(
      utxo1.hash,
      utxosRoot,
    );
    const proof2 = await smtAlice.generateCircomVerifierProof(
      utxo2.hash,
      utxosRoot,
    );
    const utxoMerkleProofs = [
      proof1.siblings.map((s) => s.bigInt()),
      proof2.siblings.map((s) => s.bigInt()),
    ];

    // Alice generates inclusion proofs for the identities in the transaction
    const identitiesRoot = await smtKyc.root();
    const proof3 = await smtKyc.generateCircomVerifierProof(
      kycHash(Alice.babyJubPublicKey),
      identitiesRoot,
    );
    const proof4 = await smtKyc.generateCircomVerifierProof(
      kycHash(Bob.babyJubPublicKey),
      identitiesRoot,
    );
    const identityMerkleProofs = [
      proof3.siblings.map((s) => s.bigInt()), // identity proof for the sender (Alice)
      proof4.siblings.map((s) => s.bigInt()), // identity proof for the 1st owner of the output UTXO (Bob)
      proof3.siblings.map((s) => s.bigInt()), // identity proof for the 2nd owner of the output UTXO (Alice)
    ];

    // Alice transfers her UTXOs to Bob
    const result2 = await doTransfer(
      Alice,
      [utxo1, utxo2],
      [nullifier1, nullifier2],
      [_utxo3, utxo4],
      utxosRoot.bigInt(),
      utxoMerkleProofs,
      identitiesRoot.bigInt(),
      identityMerkleProofs,
      [Bob, Alice],
    );

    // check the private transfer activity is not exposed in the ERC20 contract
    const afterTransferBalance = await erc20.balanceOf(Alice.ethAddress);
    expect(afterTransferBalance).to.equal(startingBalance);

    // Alice locally tracks the UTXOs inside the Sparse Merkle Tree
    await smtAlice.add(_utxo3.hash, _utxo3.hash);
    await smtAlice.add(utxo4.hash, utxo4.hash);
    utxosRoot = await smtAlice.root();
    onchainRoot = await zeto.getRoot();
    expect(utxosRoot.string()).to.equal(onchainRoot.toString());

    // Bob locally tracks the UTXOs inside the Sparse Merkle Tree
    // Bob parses the UTXOs from the onchain event
    const signerAddress = await Alice.signer.getAddress();
    const events = parseUTXOEvents(zeto, result2.txResult!);
    expect(events[0].submitter).to.equal(signerAddress);
    expect(events[0].inputs).to.deep.equal([nullifier1.hash, nullifier2.hash]);
    expect(events[0].outputs).to.deep.equal([_utxo3.hash, utxo4.hash]);
    await smtBob.add(events[0].outputs[0], events[0].outputs[0]);
    await smtBob.add(events[0].outputs[1], events[0].outputs[1]);

    // Bob uses the information received from Alice to reconstruct the UTXO sent to him
    const receivedValue = _utxo3.value!;
    const receivedSalt = _utxo3.salt;
    const incomingUTXOs: any = events[0].outputs;
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

  it("Bob transfers UTXOs, previously received from Alice, honestly to Charlie should succeed", async function () {
    // Bob generates the nullifiers for the UTXO to be spent
    const nullifier1 = newNullifier(utxo3, Bob);

    // Bob generates inclusion proofs for the UTXOs to be spent, as private input to the proof generation
    const utxosRoot = await smtBob.root();
    const proof1 = await smtBob.generateCircomVerifierProof(
      utxo3.hash,
      utxosRoot,
    );
    const proof2 = await smtBob.generateCircomVerifierProof(0n, utxosRoot);
    const utxosMerkleProofs = [
      proof1.siblings.map((s) => s.bigInt()),
      proof2.siblings.map((s) => s.bigInt()),
    ];

    // Bob proposes the output UTXOs
    utxo6 = newUTXO(10, Charlie);
    utxo7 = newUTXO(15, Bob);

    // Bob generates inclusion proofs for the identities in the transaction
    // using a shortcut with a shared SMT for all identities, but obviously
    // Bob would need his own SMT instance in a real-world scenario
    const identitiesRoot = await smtKyc.root();
    const proof3 = await smtKyc.generateCircomVerifierProof(
      kycHash(Bob.babyJubPublicKey),
      identitiesRoot,
    );
    const proof4 = await smtKyc.generateCircomVerifierProof(
      kycHash(Charlie.babyJubPublicKey),
      identitiesRoot,
    );
    const identitiesMerkleProofs = [
      proof3.siblings.map((s) => s.bigInt()), // identity proof for the sender (Bob)
      proof4.siblings.map((s) => s.bigInt()), // identity proof for the 1st owner of the output UTXO (Charlie)
      proof3.siblings.map((s) => s.bigInt()), // identity proof for the 2nd owner of the output UTXO (Bob)
    ];

    // Bob should be able to spend the UTXO that was reconstructed from the previous transaction
    const result = await doTransfer(
      Bob,
      [utxo3, ZERO_UTXO],
      [nullifier1, ZERO_UTXO],
      [utxo6, utxo7],
      utxosRoot.bigInt(),
      utxosMerkleProofs,
      identitiesRoot.bigInt(),
      identitiesMerkleProofs,
      [Charlie, Bob],
    );

    // Bob keeps the local SMT in sync
    await smtBob.add(utxo6.hash, utxo6.hash);
    await smtBob.add(utxo7.hash, utxo7.hash);

    // Alice gets the new UTXOs from the onchain event and keeps the local SMT in sync
    const events = parseUTXOEvents(zeto, result.txResult!);
    await smtAlice.add(events[0].outputs[0], events[0].outputs[0]);
    await smtAlice.add(events[0].outputs[1], events[0].outputs[1]);
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

    // Alice proposes the output UTXO as remainder of the withdrawal
    withdrawChangeUTXO = newUTXO(20, Alice);
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

  describe("unregistered user flows", function () {
    let unregisteredUtxo100: UTXO;
    let unregisteredUtxo0: UTXO;
    let smtKycUnregistered: Merkletree;

    before(async function () {
      const storage5 = new InMemoryDB(str2Bytes("unregisteredKyc"));
      smtKycUnregistered = new Merkletree(storage5, true, 10);

      await smtKycUnregistered.add(
        kycHash(Bob.babyJubPublicKey),
        kycHash(Bob.babyJubPublicKey),
      );

      // add the unregistered user to the local KYC SMT, but not to the onchain SMT
      await smtKycUnregistered.add(
        kycHash(unregistered.babyJubPublicKey),
        kycHash(unregistered.babyJubPublicKey),
      );
    });

    it("deposit by an unregistered user should fail", async function () {
      const identitiesRoot = await smtKycUnregistered.root();
      const proof3 = await smtKycUnregistered.generateCircomVerifierProof(
        kycHash(unregistered.babyJubPublicKey),
        identitiesRoot,
      );
      const identitiesMerkleProofs = [
        proof3.siblings.map((s) => s.bigInt()),
        proof3.siblings.map((s) => s.bigInt()),
      ];

      const tx = await erc20
        .connect(deployer)
        .mint(unregistered.ethAddress, 100);
      await tx.wait();
      const tx1 = await erc20
        .connect(unregistered.signer)
        .approve(zeto.target, 100);
      await tx1.wait();

      unregisteredUtxo100 = newUTXO(100, unregistered);
      unregisteredUtxo0 = newUTXO(0, unregistered);
      const { outputCommitments, encodedProof } = await prepareDepositKycProof(
        unregistered,
        [unregisteredUtxo100, unregisteredUtxo0],
        identitiesRoot.bigInt(),
        identitiesMerkleProofs,
      );
      await expect(
        zeto
          .connect(unregistered.signer)
          .deposit(
            100,
            outputCommitments,
            encodeToBytesForDeposit(encodedProof),
            "0x",
          ),
      ).to.be.rejectedWith("VM Exception while processing transaction: reverted with custom error 'InvalidProof()'");
    });
  });

  describe("ILockableCapability tests", function () {
    let utxo9: UTXO;
    let utxo10: UTXO;
    let utxo11: UTXO;
    let utxo12: UTXO;

    before(async function () {
      // mint UTXOs for Alice and spend one (to use it in a failure case test)
      utxo9 = newUTXO(10, Alice);
      utxo10 = newUTXO(15, Alice);
      await doMint(zeto, deployer, [utxo9, utxo10]);
      await smtAlice.add(utxo9.hash, utxo9.hash);
      await smtBob.add(utxo9.hash, utxo9.hash);
      await smtAlice.add(utxo10.hash, utxo10.hash);
      await smtBob.add(utxo10.hash, utxo10.hash);
    });

    it("onchain UTXOs SMT root should be equal to the offchain SMT root", async function () {
      const root = await smtAlice.root();
      const onchainRoot = await zeto.getRoot();
      expect(root.string()).to.equal(onchainRoot.toString());
    });

    it("onchain Identities SMT root should be equal to the offchain SMT root", async function () {
      const root = await smtKyc.root();
      const onchainRoot = await zeto.getIdentitiesRoot();
      expect(root.string()).to.equal(onchainRoot.toString());
    });

    it("perform a transfer to spend the new UTXO", async function () {
      // prepare the nullifier for the UTXO to be transferred
      const nullifier1 = newNullifier(utxo10, Alice);

      // prepare the UTXOs for the transfer to Bob
      utxo11 = newUTXO(15, Bob);
      utxo12 = newUTXO(0, Alice);

      let root = await smtAlice.root();
      const proof1 = await smtAlice.generateCircomVerifierProof(
        utxo10.hash,
        root,
      );
      const proof2 = await smtAlice.generateCircomVerifierProof(0n, root);
      const merkleProofs = [
        proof1.siblings.map((s) => s.bigInt()),
        proof2.siblings.map((s) => s.bigInt()),
      ];

      // Bob generates inclusion proofs for the identities in the transaction
      // using a shortcut with a shared SMT for all identities, but obviously
      // Bob would need his own SMT instance in a real-world scenario
      const identitiesRoot = await smtKyc.root();
      // generate the identity proofs for the sender (Alice)
      const proof3 = await smtKyc.generateCircomVerifierProof(
        kycHash(Alice.babyJubPublicKey),
        identitiesRoot,
      );
      // generate the identity proofs for the 1st owner of the output UTXO (Bob)
      const proof4 = await smtKyc.generateCircomVerifierProof(
        kycHash(Bob.babyJubPublicKey),
        identitiesRoot,
      );
      const identitiesMerkleProofs = [
        proof3.siblings.map((s) => s.bigInt()), // identity proof for the sender (Alice)
        proof4.siblings.map((s) => s.bigInt()), // identity proof for the 1st owner of the output UTXO (Bob)
        proof3.siblings.map((s) => s.bigInt()), // identity proof for the 2nd owner of the output UTXO (Alice)
      ];

      await doTransfer(
        Alice,
        [utxo10, ZERO_UTXO],
        [nullifier1, ZERO_UTXO],
        [utxo11, utxo12],
        root.bigInt(),
        merkleProofs,
        identitiesRoot.bigInt(),
        identitiesMerkleProofs,
        [Bob, Alice],
      );
      await smtAlice.add(utxo11.hash, utxo11.hash);
      await smtAlice.add(utxo12.hash, utxo12.hash);
      await smtBob.add(utxo11.hash, utxo11.hash);
      await smtBob.add(utxo12.hash, utxo12.hash);
    });

    // createLock -> updateLock -> delegateLock -> spendLock happy path. Note
    // that for KYC the create-lock proof is the standard transfer proof
    // (validates the SMT root and identities tree); the contract transitions
    // the locked output into a flat per-lock mapping. The spendLock proof
    // uses the dedicated transferLocked circuit / verifier wired through the
    // ignition module's lockVerifier slot.
    describe("createLock -> updateLock -> delegateLock -> spendLock flow", function () {
      let lockedUtxo1: UTXO;
      let lockId: string;
      let outputUtxo1: UTXO;
      let outputUtxo2: UTXO;
      let unlockHash: string;
      // Local SMT mirroring on-chain locked-state bookkeeping used by
      // delegateLock tests (`locked()` / storage mirrors).
      let smtForLocked: Merkletree;

      before(async function () {
        const storage = new InMemoryDB(str2Bytes("kyc-locked-1"));
        smtForLocked = new Merkletree(storage, true, 64);
      });

      it("createLock() with deterministic lockId computed from txId", async function () {
        const nullifier1 = newNullifier(utxo11, Bob);
        lockedUtxo1 = newUTXO(utxo11.value!, Bob);
        const root = await smtBob.root();
        const p1 = await smtBob.generateCircomVerifierProof(utxo11.hash, root);
        const p2 = await smtBob.generateCircomVerifierProof(0n, root);
        const merkleProofs = [
          p1.siblings.map((s) => s.bigInt()),
          p2.siblings.map((s) => s.bigInt()),
        ];

        const identitiesRoot = await smtKyc.root();
        const idProofBob = await smtKyc.generateCircomVerifierProof(
          kycHash(Bob.babyJubPublicKey),
          identitiesRoot,
        );
        const identityMerkleProofs = [
          idProofBob.siblings.map((s) => s.bigInt()), // sender (Bob)
          idProofBob.siblings.map((s) => s.bigInt()), // 1st output owner (Bob)
          idProofBob.siblings.map((s) => s.bigInt()), // 2nd output owner (dummy)
        ];

        const { encodedProof } = await prepareProof(
          circuit,
          provingKey,
          Bob,
          [utxo11, ZERO_UTXO],
          [nullifier1, ZERO_UTXO],
          [lockedUtxo1, ZERO_UTXO],
          root.bigInt(),
          merkleProofs,
          identitiesRoot.bigInt(),
          identityMerkleProofs,
          [Bob, Bob],
        );

        const txId = randomBytes32();
        const createArgs = encodeCreateArgs({
          txId,
          inputs: [nullifier1.hash],
          outputs: [],
          lockedOutputs: [lockedUtxo1.hash],
          proof: encodeUnlockedProof(root.bigInt(), encodedProof),
        });

        // Pre-compute lockId off-chain and confirm against the contract.
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

        // Mirror the locked UTXO into the local SMT so the locked-circuit
        // witness has a valid inclusion proof to consume.
        await smtForLocked.add(
          lockedUtxo1.hash,
          ethers.toBigInt(Bob.ethAddress),
        );
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
        // utxo12 is an unlocked UTXO that still belongs to Alice.
        expect((await zeto.locked(utxo12.hash))[0]).to.be.false;
      });

      it("updateLock() commits the spend hash while owner == spender", async function () {
        outputUtxo1 = newUTXO(10, Alice);
        outputUtxo2 = newUTXO(5, Bob);

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
        // Storage-layer delegate must follow the spender.
        expect(await zeto.locked(lockedUtxo1.hash)).to.deep.equal([
          true,
          Alice.ethAddress,
        ]);
        // Mirror the new delegate into the local locked SMT so the spendLock
        // witness's SMT inclusion proof matches the (utxoHash, delegate) leaf.
        await smtForLocked.update(
          lockedUtxo1.hash,
          ethers.toBigInt(Alice.ethAddress),
        );
      });

      it("the new spender can spendLock() with the matching payload", async function () {
        // The locked-input proof is generated against the dedicated
        // transferLocked circuit; identity-tree membership for both the
        // (still-original) sender Bob and each output owner is asserted as
        // part of the snark, mirroring the unlocked transfer flow.
        const nullifier1 = newNullifier(lockedUtxo1, Bob);
        const identitiesRoot = await smtKyc.root();
        const idProofBob = await smtKyc.generateCircomVerifierProof(
          kycHash(Bob.babyJubPublicKey),
          identitiesRoot,
        );
        const idProofAlice = await smtKyc.generateCircomVerifierProof(
          kycHash(Alice.babyJubPublicKey),
          identitiesRoot,
        );
        const identityMerkleProofs = [
          idProofBob.siblings.map((s) => s.bigInt()), // sender (Bob)
          idProofAlice.siblings.map((s) => s.bigInt()), // 1st output owner (Alice)
          idProofBob.siblings.map((s) => s.bigInt()), // 2nd output owner (Bob)
        ];

        const { encodedProof } = await prepareProof(
          circuitForLocked,
          provingKeyForLocked,
          Bob,
          [lockedUtxo1, ZERO_UTXO],
          [nullifier1, ZERO_UTXO],
          [outputUtxo1, outputUtxo2],
          0n,
          [],
          identitiesRoot.bigInt(),
          identityMerkleProofs,
          [Alice, Bob],
          undefined,
          { transferLocked: true },
        );

        const spendArgs = encodeSpendArgs({
          txId: randomBytes32(),
          lockedOutputs: [],
          outputs: [outputUtxo1.hash, outputUtxo2.hash],
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

        // Lock is no longer active after spendLock().
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

    // createLock with a non-zero cancelCommitment, then cancelLock by the
    // owner without going through delegateLock. Cancelling a lock follows
    // the same proof-encoding rules as spendLock (locked-input verifier,
    // bare Commonlib.Proof) but is gated by the cancelCommitment hash.
    describe("createLock -> cancelLock flow", function () {
      let lockedUtxo: UTXO;
      let lockId: string;
      let cancelHash: string;
      let outUtxo1: UTXO;
      let outUtxo2: UTXO;
      let aliceUtxoForLock: UTXO;
      let smtForLocked: Merkletree;

      before(async function () {
        // Mint a fresh source UTXO for Alice so this scope can build its own
        // lock without colliding with the prior describe block's spend flow.
        aliceUtxoForLock = newUTXO(50, Alice);
        await doMint(zeto, deployer, [aliceUtxoForLock]);
        await smtAlice.add(aliceUtxoForLock.hash, aliceUtxoForLock.hash);
        await smtBob.add(aliceUtxoForLock.hash, aliceUtxoForLock.hash);
        const storage = new InMemoryDB(str2Bytes("kyc-locked-2"));
        smtForLocked = new Merkletree(storage, true, 64);
      });

      it("Alice createLock() with a cancelCommitment", async function () {
        const nullifier1 = newNullifier(aliceUtxoForLock, Alice);
        lockedUtxo = newUTXO(aliceUtxoForLock.value!, Alice);
        const root = await smtAlice.root();
        const p1 = await smtAlice.generateCircomVerifierProof(
          aliceUtxoForLock.hash,
          root,
        );
        const p2 = await smtAlice.generateCircomVerifierProof(0n, root);
        const merkleProofs = [
          p1.siblings.map((s) => s.bigInt()),
          p2.siblings.map((s) => s.bigInt()),
        ];

        const identitiesRoot = await smtKyc.root();
        const idProofAlice = await smtKyc.generateCircomVerifierProof(
          kycHash(Alice.babyJubPublicKey),
          identitiesRoot,
        );
        const identityMerkleProofs = [
          idProofAlice.siblings.map((s) => s.bigInt()),
          idProofAlice.siblings.map((s) => s.bigInt()),
          idProofAlice.siblings.map((s) => s.bigInt()),
        ];

        const { encodedProof } = await prepareProof(
          circuit,
          provingKey,
          Alice,
          [aliceUtxoForLock, ZERO_UTXO],
          [nullifier1, ZERO_UTXO],
          [lockedUtxo, ZERO_UTXO],
          root.bigInt(),
          merkleProofs,
          identitiesRoot.bigInt(),
          identityMerkleProofs,
          [Alice, Alice],
        );

        outUtxo1 = newUTXO(20, Bob);
        outUtxo2 = newUTXO(30, Alice);
        cancelHash = calculateCancelHash(
          [lockedUtxo],
          [],
          [outUtxo1, outUtxo2],
          "0x",
        );

        const createArgs = encodeCreateArgs({
          txId: randomBytes32(),
          inputs: [nullifier1.hash],
          outputs: [],
          lockedOutputs: [lockedUtxo.hash],
          proof: encodeUnlockedProof(root.bigInt(), encodedProof),
        });
        lockId = await zeto.connect(Alice.signer).computeLockId(createArgs);

        const tx = await zeto
          .connect(Alice.signer)
          .createLock(createArgs, ethers.ZeroHash, cancelHash, "0x");
        const result: ContractTransactionReceipt | null = await tx.wait();
        logger.debug(`createLock() complete. Gas used: ${result?.gasUsed}`);

        // Mirror the locked UTXO so the cancel-side witness can prove inclusion.
        await smtForLocked.add(
          lockedUtxo.hash,
          ethers.toBigInt(Alice.ethAddress),
        );
      });

      it("the owner can cancelLock() to reverse the lock without delegation", async function () {
        const nullifier1 = newNullifier(lockedUtxo, Alice);
        const identitiesRoot = await smtKyc.root();
        const idProofAlice = await smtKyc.generateCircomVerifierProof(
          kycHash(Alice.babyJubPublicKey),
          identitiesRoot,
        );
        const idProofBob = await smtKyc.generateCircomVerifierProof(
          kycHash(Bob.babyJubPublicKey),
          identitiesRoot,
        );
        const identityMerkleProofs = [
          idProofAlice.siblings.map((s) => s.bigInt()), // sender (Alice)
          idProofBob.siblings.map((s) => s.bigInt()), // 1st output owner (Bob)
          idProofAlice.siblings.map((s) => s.bigInt()), // 2nd output owner (Alice)
        ];

        const { encodedProof } = await prepareProof(
          circuitForLocked,
          provingKeyForLocked,
          Alice,
          [lockedUtxo, ZERO_UTXO],
          [nullifier1, ZERO_UTXO],
          [outUtxo1, outUtxo2],
          0n,
          [],
          identitiesRoot.bigInt(),
          identityMerkleProofs,
          [Bob, Alice],
          undefined,
          { transferLocked: true },
        );

        const cancelArgs = encodeSpendArgs({
          txId: randomBytes32(),
          lockedOutputs: [],
          outputs: [outUtxo1.hash, outUtxo2.hash],
          proof: encodeLockedProof(encodedProof),
          data: "0x",
        });

        const tx = await zeto
          .connect(Alice.signer)
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

        const outputs = zetoCancelled!.args.outputs;
        await smtAlice.add(outputs[0], outputs[0]);
        await smtAlice.add(outputs[1], outputs[1]);
        await smtBob.add(outputs[0], outputs[0]);
        await smtBob.add(outputs[1], outputs[1]);

        expect(await zeto.isLockActive(lockId)).to.equal(false);
      });
    });

    // Negative cases for the lock lifecycle. These rely on hardhat's revert
    // decoding for custom errors and so are gated by the network name.
    describe("negative cases for the lock lifecycle", function () {
      if (network.name !== "hardhat") {
        return;
      }

      // freshLock mints a fresh UTXO for `owner`, locks it, and returns the
      // metadata so each negative scope can branch off without polluting
      // siblings. Each call advances both local SMTs.
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
        const sourceUtxo = newUTXO(7, owner);
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

        const identitiesRoot = await smtKyc.root();
        const idProofOwner = await smtKyc.generateCircomVerifierProof(
          kycHash(owner.babyJubPublicKey),
          identitiesRoot,
        );
        const identityMerkleProofs = [
          idProofOwner.siblings.map((s) => s.bigInt()),
          idProofOwner.siblings.map((s) => s.bigInt()),
          idProofOwner.siblings.map((s) => s.bigInt()),
        ];

        const { encodedProof } = await prepareProof(
          circuit,
          provingKey,
          owner,
          [sourceUtxo, ZERO_UTXO],
          [nullifier, ZERO_UTXO],
          [lockedUtxo, ZERO_UTXO],
          root.bigInt(),
          merkleProofs,
          identitiesRoot.bigInt(),
          identityMerkleProofs,
          [owner, owner],
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

      // Authorization / immutability assertions short-circuit before the
      // proof is ever touched, so we can pass a syntactically valid but
      // ZK-vacuous spend payload.
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
        ).rejectedWith(`DuplicateLock("${lockId}")`);
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
        ).to.be.revertedWithCustomError(zeto, "LockUnauthorized")
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
        ).rejectedWith(`LockImmutable("${lockId}")`);
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
    });
  });

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

      // Alice proposes the output UTXO as remainder of the withdrawal
      withdrawChangeUTXO = newUTXO(90, Alice);
      const { nullifiers, outputCommitments, encodedProof } =
        await prepareNullifierWithdrawProof(
          Alice,
          [utxo100, ZERO_UTXO],
          [nullifier1, ZERO_UTXO],
          withdrawChangeUTXO,
          root.bigInt(),
          merkleProofs,
        );

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

      const identitiesRoot = await smtKyc.root();
      const proof3 = await smtKyc.generateCircomVerifierProof(
        kycHash(Alice.babyJubPublicKey),
        identitiesRoot,
      );
      const proof4 = await smtKyc.generateCircomVerifierProof(
        kycHash(Bob.babyJubPublicKey),
        identitiesRoot,
      );
      const identitiesMerkleProofs = [
        proof3.siblings.map((s) => s.bigInt()), // identity proof for the sender (Alice)
        proof4.siblings.map((s) => s.bigInt()), // identity proof for the 1st owner of the output UTXO (Bob)
        proof3.siblings.map((s) => s.bigInt()), // identity proof for the 2nd owner of the output UTXO (Alice)
      ];

      await expect(
        doTransfer(
          Alice,
          [utxo1, utxo2],
          [nullifier1, nullifier2],
          [_utxo1, _utxo2],
          root.bigInt(),
          merkleProofs,
          identitiesRoot.bigInt(),
          identitiesMerkleProofs,
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

      const identitiesRoot = await smtKyc.root();
      const proof3 = await smtKyc.generateCircomVerifierProof(
        kycHash(Bob.babyJubPublicKey),
        identitiesRoot,
      );
      const proof4 = await smtKyc.generateCircomVerifierProof(
        kycHash(Alice.babyJubPublicKey),
        identitiesRoot,
      );
      const identitiesMerkleProofs = [
        proof3.siblings.map((s) => s.bigInt()), // identity proof for the sender (Bob)
        proof4.siblings.map((s) => s.bigInt()), // identity proof for the 1st owner of the output UTXO (Alice)
        proof4.siblings.map((s) => s.bigInt()), // identity proof for the 2nd owner of the output UTXO (Alice)
      ];

      await expect(
        doTransfer(
          Bob,
          [utxo7, _utxo1],
          [nullifier1, nullifier2],
          [utxo1, utxo2],
          root.bigInt(),
          merkleProofs,
          identitiesRoot.bigInt(),
          identitiesMerkleProofs,
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

      const identitiesRoot = await smtKyc.root();
      const proof3 = await smtKyc.generateCircomVerifierProof(
        kycHash(Bob.babyJubPublicKey),
        identitiesRoot,
      );
      const proof4 = await smtKyc.generateCircomVerifierProof(
        kycHash(Alice.babyJubPublicKey),
        identitiesRoot,
      );
      const identitiesMerkleProofs = [
        proof3.siblings.map((s) => s.bigInt()), // identity proof for the sender (Bob)
        proof4.siblings.map((s) => s.bigInt()), // identity proof for the 1st owner of the output UTXO (Alice)
        proof3.siblings.map((s) => s.bigInt()), // identity proof for the 2nd owner of the output UTXO (Bob)
      ];

      await expect(
        doTransfer(
          Bob,
          [utxo7, utxo7],
          [nullifier1, nullifier2],
          [_utxo1, _utxo2],
          root.bigInt(),
          merkleProofs,
          identitiesRoot.bigInt(),
          identitiesMerkleProofs,
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
      const utxo7 = newUTXO(15, Bob);

      const identitiesRoot = await smtKyc.root();
      const proof3 = await smtKyc.generateCircomVerifierProof(
        kycHash(Alice.babyJubPublicKey),
        identitiesRoot,
      );
      const proof4 = await smtKyc.generateCircomVerifierProof(
        kycHash(Bob.babyJubPublicKey),
        identitiesRoot,
      );
      const proof5 = await smtKyc.generateCircomVerifierProof(
        kycHash(Charlie.babyJubPublicKey),
        identitiesRoot,
      );
      const identitiesMerkleProofs = [
        proof3.siblings.map((s) => s.bigInt()), // identity proof for the sender (Alice)
        proof4.siblings.map((s) => s.bigInt()), // identity proof for the 1st owner of the output UTXO (Bob)
        proof5.siblings.map((s) => s.bigInt()), // identity proof for the 2nd owner of the output UTXO (Charlie)
      ];

      await expect(
        doTransfer(
          Alice,
          [nonExisting1, nonExisting2],
          [nullifier1, nullifier2],
          [utxo7, _utxo1],
          root.bigInt(),
          merkleProofs,
          identitiesRoot.bigInt(),
          identitiesMerkleProofs,
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
    utxosRoot: BigInt,
    utxosMerkleProofs: BigInt[][],
    identitiesRoot: BigInt,
    identitiesMerkleProof: BigInt[][],
    owners: User[],
  ) {
    let nullifiers: BigNumberish[];
    let outputCommitments: BigNumberish[];
    let encodedProof: any;
    let circuitToUse = circuit;
    let provingKeyToUse = provingKey;
    if (inputs.length > 2 || outputs.length > 2) {
      // if there are more than 2 inputs, we use the circuit for batching
      circuitToUse = batchCircuit;
      provingKeyToUse = batchProvingKey;
    }
    const result = await prepareProof(
      circuitToUse,
      provingKeyToUse,
      signer,
      inputs,
      _nullifiers,
      outputs,
      utxosRoot,
      utxosMerkleProofs,
      identitiesRoot,
      identitiesMerkleProof,
      owners,
    );
    nullifiers = _nullifiers.map((nullifier) => nullifier.hash) as [
      BigNumberish,
      BigNumberish,
    ];
    outputCommitments = result.outputCommitments;
    encodedProof = result.encodedProof;

    const txResult = await sendTx(
      signer,
      nullifiers,
      outputCommitments,
      utxosRoot,
      encodedProof,
    );
    return {
      txResult,
    };
  }

  async function prepareProof(
    circuit: any,
    provingKey: any,
    signer: User,
    inputs: UTXO[],
    _nullifiers: UTXO[],
    outputs: UTXO[],
    utxosRoot: BigInt,
    utxosMerkleProof: BigInt[][],
    identitiesRoot: BigInt,
    identitiesMerkleProof: BigInt[][],
    owners: User[],
    lockDelegate?: string,
    opts?: { transferLocked?: boolean },
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

    let inputObj: any;
    if (opts?.transferLocked) {
      inputObj = {
        inputCommitments,
        inputValues,
        inputSalts,
        inputOwnerPrivateKey: signer.formattedPrivateKey,
        identitiesRoot,
        identitiesMerkleProof,
        outputCommitments,
        outputValues,
        outputSalts: outputs.map((output) => output.salt || 0n),
        outputOwnerPublicKeys,
      };
    } else {
      inputObj = {
        nullifiers,
        inputCommitments,
        inputValues,
        inputSalts,
        inputOwnerPrivateKey: signer.formattedPrivateKey,
        utxosRoot,
        enabled: nullifiers.map((n) => (n !== 0n ? 1 : 0)),
        utxosMerkleProof,
        identitiesRoot,
        identitiesMerkleProof,
        outputCommitments,
        outputValues,
        outputSalts: outputs.map((output) => output.salt || 0n),
        outputOwnerPublicKeys,
      };
      if (lockDelegate) {
        inputObj["lockDelegate"] = ethers.toBigInt(lockDelegate);
      }
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
    return {
      inputCommitments,
      outputCommitments,
      encodedProof,
    };
  }

  async function sendTx(
    signer: User,
    nullifiers: BigNumberish[],
    outputCommitments: BigNumberish[],
    root: BigNumberish,
    encodedProof: any,
  ) {
    const startTx = Date.now();
    const tx = await zeto.connect(signer.signer).transfer(
      nullifiers.filter((ic) => ic !== 0n), // trim off empty utxo hashes to check padding logic for batching works
      outputCommitments.filter((oc) => oc !== 0n), // trim off empty utxo hashes to check padding logic for batching works
      encodeToBytes(root, encodedProof),
      "0x",
    );
    const results: ContractTransactionReceipt | null = await tx.wait();
    console.log(
      `Time to execute transaction: ${Date.now() - startTx}ms. Gas used: ${results?.gasUsed
      }`,
    );
    return results;
  }
});

function encodeToBytes(root: any, proof: any) {
  return new AbiCoder().encode(
    ["uint256 root", "tuple(uint256[2] pA, uint256[2][2] pB, uint256[2] pC)"],
    [root, proof],
  );
}
