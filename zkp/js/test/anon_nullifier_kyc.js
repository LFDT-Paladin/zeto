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

const { expect } = require("chai");
const { join } = require("path");
const { wasm: wasm_tester } = require("circom_tester");
const { genKeypair, formatPrivKeyForBabyJub } = require("maci-crypto");
const {
  Merkletree,
  InMemoryDB,
  str2Bytes,
  ZERO_HASH,
} = require("@iden3/js-merkletree");
const { Poseidon, newSalt, kycHash } = require("../index.js");

const SMT_HEIGHT_UTXO = 64;
const SMT_HEIGHT_IDENTITY = 10;
const poseidonHash = Poseidon.poseidon4;
const poseidonHash2 = Poseidon.poseidon2;
const poseidonHash3 = Poseidon.poseidon3;

describe("main circuit tests for Zeto fungible tokens with anonymity, KYC, using nullifiers and without encryption", () => {
  let circuit, smtAlice, smtKYC, smtBob;

  const Alice = {};
  const Bob = {};
  let senderPrivateKey;

  before(async function () {
    this.timeout(60000);

    circuit = await wasm_tester(
      join(__dirname, "../../circuits/anon_nullifier_kyc_transfer.circom"),
    );

    let keypair = genKeypair();
    Alice.privKey = keypair.privKey;
    Alice.pubKey = keypair.pubKey;
    senderPrivateKey = formatPrivKeyForBabyJub(Alice.privKey);

    keypair = genKeypair();
    Bob.privKey = keypair.privKey;
    Bob.pubKey = keypair.pubKey;

    // initialize the local storage for Alice to manage her UTXOs in the Spart Merkle Tree
    const storage1 = new InMemoryDB(str2Bytes("alice"));
    smtAlice = new Merkletree(storage1, true, SMT_HEIGHT_UTXO);

    // initialize the local storage for Bob to manage his UTXOs in the Spart Merkle Tree
    const storage2 = new InMemoryDB(str2Bytes("bob"));
    smtBob = new Merkletree(storage2, true, SMT_HEIGHT_UTXO);

    // initialize the local storage for the sender to manage identities in the Spart Merkle Tree
    const storage3 = new InMemoryDB(str2Bytes("kyc"));
    smtKYC = new Merkletree(storage3, true, SMT_HEIGHT_IDENTITY);

    // calculate the identity hash for Alice
    const identity1 = poseidonHash2(Alice.pubKey);
    await smtKYC.add(identity1, identity1);

    // calculate the identity hash for Bob
    const identity2 = poseidonHash2(Bob.pubKey);
    await smtKYC.add(identity2, identity2);
  });

  it("should succeed for valid witness", async () => {
    const inputValues = [32, 40];
    const outputValues = [20, 52];

    // create two input UTXOs, each has their own salt, but same owner
    const salt1 = newSalt();
    const input1 = poseidonHash([
      BigInt(inputValues[0]),
      salt1,
      ...Alice.pubKey,
    ]);
    const salt2 = newSalt();
    const input2 = poseidonHash([
      BigInt(inputValues[1]),
      salt2,
      ...Alice.pubKey,
    ]);
    const inputCommitments = [input1, input2];

    // create the nullifiers for the inputs
    const nullifier1 = poseidonHash3([
      BigInt(inputValues[0]),
      salt1,
      senderPrivateKey,
    ]);
    const nullifier2 = poseidonHash3([
      BigInt(inputValues[1]),
      salt2,
      senderPrivateKey,
    ]);
    const nullifiers = [nullifier1, nullifier2];

    // calculate the root of the SMT
    await smtAlice.add(input1, input1);
    await smtAlice.add(input2, input2);

    // generate the merkle proof for the inputs
    const proof1 = await smtAlice.generateCircomVerifierProof(
      input1,
      ZERO_HASH,
    );
    const proof2 = await smtAlice.generateCircomVerifierProof(
      input2,
      ZERO_HASH,
    );
    const utxosRoot = proof1.root.bigInt();

    // create two output UTXOs, they share the same salt, and different owner
    const salt3 = newSalt();
    const output1 = poseidonHash([
      BigInt(outputValues[0]),
      salt3,
      ...Bob.pubKey,
    ]);
    const salt4 = newSalt();
    const output2 = poseidonHash([
      BigInt(outputValues[1]),
      salt4,
      ...Alice.pubKey,
    ]);
    const outputCommitments = [output1, output2];

    // generate the merkle proof for the transacting identities
    const proof3 = await smtKYC.generateCircomVerifierProof(
      poseidonHash2(Alice.pubKey),
      ZERO_HASH,
    );
    const proof4 = await smtKYC.generateCircomVerifierProof(
      poseidonHash2(Bob.pubKey),
      ZERO_HASH,
    );
    const identitiesRoot = proof3.root.bigInt();

    const witness = await circuit.calculateWitness(
      {
        nullifiers,
        inputCommitments,
        inputValues,
        inputSalts: [salt1, salt2],
        inputOwnerPrivateKey: senderPrivateKey,
        utxosRoot,
        utxosMerkleProof: [
          proof1.siblings.map((s) => s.bigInt()),
          proof2.siblings.map((s) => s.bigInt()),
        ],
        enabled: [1, 1],
        identitiesRoot,
        identitiesMerkleProof: [
          proof3.siblings.map((s) => s.bigInt()),
          proof4.siblings.map((s) => s.bigInt()),
          proof3.siblings.map((s) => s.bigInt()),
        ],
        outputCommitments,
        outputValues,
        outputSalts: [salt3, salt4],
        outputOwnerPublicKeys: [Bob.pubKey, Alice.pubKey],
      },
      true,
    );

    // console.log('witness', witness.slice(0, 20));
    // console.log('nullifiers', nullifiers);
    // console.log('inputCommitments', inputCommitments);
    // console.log('inputValues', inputValues);
    // console.log('inputSalts', [salt1, salt2]);
    // console.log('outputCommitments', outputCommitments);
    // console.log('utxosRoot', proof1.root.bigInt());
    // console.log('outputValues', outputValues);
    // console.log('outputSalt', salt3);
    // console.log('outputOwnerPublicKeys', [Bob.pubKey, Alice.pubKey]);
    // console.log('identitiesRoot', proof3.root.bigInt());

    expect(witness[1]).to.equal(BigInt(nullifiers[0]));
    expect(witness[2]).to.equal(BigInt(nullifiers[1]));
    expect(witness[3]).to.equal(proof1.root.bigInt());
    expect(witness[6]).to.equal(proof3.root.bigInt());
  });

  it("should succeed for valid witness when using empty output commitments", async () => {
    const inputValues = [32, 40];
    const outputValues = [72, 0];

    // create two input UTXOs, each has their own salt, but same owner
    const salt1 = newSalt();
    const input1 = poseidonHash([
      BigInt(inputValues[0]),
      salt1,
      ...Alice.pubKey,
    ]);
    const salt2 = newSalt();
    const input2 = poseidonHash([
      BigInt(inputValues[1]),
      salt2,
      ...Alice.pubKey,
    ]);
    const inputCommitments = [input1, input2];

    // create the nullifiers for the inputs
    const nullifier1 = poseidonHash3([
      BigInt(inputValues[0]),
      salt1,
      senderPrivateKey,
    ]);
    const nullifier2 = poseidonHash3([
      BigInt(inputValues[1]),
      salt2,
      senderPrivateKey,
    ]);
    const nullifiers = [nullifier1, nullifier2];

    // calculate the root of the SMT
    await smtAlice.add(input1, input1);
    await smtAlice.add(input2, input2);

    // generate the merkle proof for the inputs
    const proof1 = await smtAlice.generateCircomVerifierProof(
      input1,
      ZERO_HASH,
    );
    const proof2 = await smtAlice.generateCircomVerifierProof(
      input2,
      ZERO_HASH,
    );
    const utxosRoot = proof1.root.bigInt();

    // create two output UTXOs, they share the same salt, and different owner
    const salt3 = newSalt();
    const salt4 = newSalt();
    const output2 = poseidonHash([
      BigInt(outputValues[1]),
      salt4,
      ...Alice.pubKey,
    ]);
    const outputCommitments = [0, output2];

    // generate the merkle proof for the transacting identities
    const proof3 = await smtKYC.generateCircomVerifierProof(
      poseidonHash2(Alice.pubKey),
      ZERO_HASH,
    );
    const proof4 = await smtKYC.generateCircomVerifierProof(
      poseidonHash2(Bob.pubKey),
      ZERO_HASH,
    );
    const identitiesRoot = proof3.root.bigInt();

    const witness = await circuit.calculateWitness(
      {
        nullifiers,
        inputCommitments,
        inputValues,
        inputSalts: [salt1, salt2],
        inputOwnerPrivateKey: senderPrivateKey,
        utxosRoot,
        utxosMerkleProof: [
          proof1.siblings.map((s) => s.bigInt()),
          proof2.siblings.map((s) => s.bigInt()),
        ],
        enabled: [1, 1],
        identitiesRoot,
        identitiesMerkleProof: [
          proof3.siblings.map((s) => s.bigInt()),
          proof4.siblings.map((s) => s.bigInt()),
          proof3.siblings.map((s) => s.bigInt()),
        ],
        outputCommitments,
        outputValues,
        outputSalts: [0, salt4],
        outputOwnerPublicKeys: [Bob.pubKey, Alice.pubKey],
      },
      true,
    );

    // console.log('witness', witness.slice(0, 20));
    // console.log('nullifiers', nullifiers);
    // console.log('inputCommitments', inputCommitments);
    // console.log('inputValues', inputValues);
    // console.log('inputSalts', [salt1, salt2]);
    // console.log('outputCommitments', outputCommitments);
    // console.log('utxosRoot', proof1.root.bigInt());
    // console.log('outputValues', outputValues);
    // console.log('outputSalt', salt3);
    // console.log('outputOwnerPublicKeys', [Bob.pubKey, Alice.pubKey]);
    // console.log('identitiesRoot', proof3.root.bigInt());

    expect(witness[1]).to.equal(BigInt(nullifiers[0]));
    expect(witness[2]).to.equal(BigInt(nullifiers[1]));
    expect(witness[3]).to.equal(proof1.root.bigInt());
    expect(witness[6]).to.equal(proof3.root.bigInt());
  });

  it("should fail if not using the right identities merkle proofs", async () => {
    const inputValues = [32, 40];
    const outputValues = [20, 52];

    // create two input UTXOs, each has their own salt, but same owner
    const salt1 = newSalt();
    const input1 = poseidonHash([
      BigInt(inputValues[0]),
      salt1,
      ...Alice.pubKey,
    ]);
    const salt2 = newSalt();
    const input2 = poseidonHash([
      BigInt(inputValues[1]),
      salt2,
      ...Alice.pubKey,
    ]);
    const inputCommitments = [input1, input2];

    // create the nullifiers for the inputs
    const nullifier1 = poseidonHash3([
      BigInt(inputValues[0]),
      salt1,
      senderPrivateKey,
    ]);
    const nullifier2 = poseidonHash3([
      BigInt(inputValues[1]),
      salt2,
      senderPrivateKey,
    ]);
    const nullifiers = [nullifier1, nullifier2];

    // calculate the root of the SMT
    await smtAlice.add(input1, input1);
    await smtAlice.add(input2, input2);

    // generate the merkle proof for the inputs
    const proof1 = await smtAlice.generateCircomVerifierProof(
      input1,
      ZERO_HASH,
    );
    const proof2 = await smtAlice.generateCircomVerifierProof(
      input2,
      ZERO_HASH,
    );
    const utxosRoot = proof1.root.bigInt();

    // create two output UTXOs, they share the same salt, and different owner
    const salt3 = newSalt();
    const output1 = poseidonHash([
      BigInt(outputValues[0]),
      salt3,
      ...Bob.pubKey,
    ]);
    const salt4 = newSalt();
    const output2 = poseidonHash([
      BigInt(outputValues[1]),
      salt4,
      ...Alice.pubKey,
    ]);
    const outputCommitments = [output1, output2];

    // generate the merkle proof for the transacting identities
    const proof3 = await smtKYC.generateCircomVerifierProof(
      poseidonHash2(Alice.pubKey),
      ZERO_HASH,
    );
    const proof4 = await smtKYC.generateCircomVerifierProof(
      poseidonHash2(Bob.pubKey),
      ZERO_HASH,
    );
    const identitiesRoot = proof3.root.bigInt();

    let error;
    try {
      await circuit.calculateWitness(
        {
          nullifiers,
          inputCommitments,
          inputValues,
          inputSalts: [salt1, salt2],
          inputOwnerPrivateKey: senderPrivateKey,
          utxosRoot,
          utxosMerkleProof: [
            proof1.siblings.map((s) => s.bigInt()),
            proof2.siblings.map((s) => s.bigInt()),
          ],
          enabled: [1, 1],
          identitiesRoot,
          identitiesMerkleProof: [
            proof3.siblings.map((s) => s.bigInt()),
            proof4.siblings.map((s) => s.bigInt()),
            [0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n], // invalid MTP
          ],
          outputCommitments,
          outputValues,
          outputSalts: [salt3, salt4],
          outputOwnerPublicKeys: [Bob.pubKey, Alice.pubKey],
        },
        true,
      );
    } catch (e) {
      error = e;
    }
    // console.log(error);
    expect(error).to.match(/Error in template CheckSMTProof_253 line: 38/);
  });
});

// Locked-input transfer for the KYC nullifier-based token. Under the new
// ILockableCapability storage, locked UTXOs live in a flat per-lock
// mapping rather than the unlocked-UTXO SMT, so this circuit drops the
// nullifiers and the UTXO-tree merkle inputs that the unlocked variant
// asserts against. What remains: sender-ownership (BabyJubjub key
// derivation), commitment-hash binding for both sides, sum conservation,
// and KYC inclusion for the sender + each non-zero output owner.
describe("main circuit tests for Zeto fungible tokens with anonymity, KYC, using nullifiers without encryption (locked-input transfer)", () => {
  let circuit, smtKYC;

  const Alice = {};
  const Bob = {};
  let senderPrivateKey;

  before(async function () {
    this.timeout(60000);

    circuit = await wasm_tester(
      join(__dirname, "../../circuits/anon_nullifier_kyc_transferLocked.circom"),
    );

    let keypair = genKeypair();
    Alice.privKey = keypair.privKey;
    Alice.pubKey = keypair.pubKey;
    senderPrivateKey = formatPrivKeyForBabyJub(Alice.privKey);

    keypair = genKeypair();
    Bob.privKey = keypair.privKey;
    Bob.pubKey = keypair.pubKey;

    // initialize the local storage for the sender to manage identities in the Sparse Merkle Tree
    const storage = new InMemoryDB(str2Bytes("kyc-locked"));
    smtKYC = new Merkletree(storage, true, SMT_HEIGHT_IDENTITY);

    const identity1 = poseidonHash2(Alice.pubKey);
    await smtKYC.add(identity1, identity1);

    const identity2 = poseidonHash2(Bob.pubKey);
    await smtKYC.add(identity2, identity2);
  });

  it("should succeed for valid witness", async () => {
    const inputValues = [32, 40];
    const outputValues = [20, 52];

    // build the locked input commitments — the on-chain lockable storage
    // treats these as raw UTXO hashes (no nullifier wrapping).
    const salt1 = newSalt();
    const input1 = poseidonHash([
      BigInt(inputValues[0]),
      salt1,
      ...Alice.pubKey,
    ]);
    const salt2 = newSalt();
    const input2 = poseidonHash([
      BigInt(inputValues[1]),
      salt2,
      ...Alice.pubKey,
    ]);
    const inputCommitments = [input1, input2];

    // outputs go to Bob and back to Alice as change.
    const salt3 = newSalt();
    const output1 = poseidonHash([
      BigInt(outputValues[0]),
      salt3,
      ...Bob.pubKey,
    ]);
    const salt4 = newSalt();
    const output2 = poseidonHash([
      BigInt(outputValues[1]),
      salt4,
      ...Alice.pubKey,
    ]);
    const outputCommitments = [output1, output2];

    // identities merkle proofs for sender (Alice) + each output owner.
    const proofAlice = await smtKYC.generateCircomVerifierProof(
      poseidonHash2(Alice.pubKey),
      ZERO_HASH,
    );
    const proofBob = await smtKYC.generateCircomVerifierProof(
      poseidonHash2(Bob.pubKey),
      ZERO_HASH,
    );
    const identitiesRoot = proofAlice.root.bigInt();

    const witness = await circuit.calculateWitness(
      {
        inputCommitments,
        inputValues,
        inputSalts: [salt1, salt2],
        inputOwnerPrivateKey: senderPrivateKey,
        identitiesRoot,
        identitiesMerkleProof: [
          proofAlice.siblings.map((s) => s.bigInt()), // sender (Alice)
          proofBob.siblings.map((s) => s.bigInt()), // 1st output owner (Bob)
          proofAlice.siblings.map((s) => s.bigInt()), // 2nd output owner (Alice)
        ],
        outputCommitments,
        outputValues,
        outputSalts: [salt3, salt4],
        outputOwnerPublicKeys: [Bob.pubKey, Alice.pubKey],
      },
      true,
    );

    // public-input order matches the wrapper's
    // `public [ inputCommitments, identitiesRoot, outputCommitments ]`
    // declaration, so the witness lays out
    // [1, input1, input2, identitiesRoot, output1, output2, ...].
    expect(witness[1]).to.equal(BigInt(inputCommitments[0]));
    expect(witness[2]).to.equal(BigInt(inputCommitments[1]));
    expect(witness[3]).to.equal(identitiesRoot);
    expect(witness[4]).to.equal(BigInt(outputCommitments[0]));
    expect(witness[5]).to.equal(BigInt(outputCommitments[1]));
  });

  it("should succeed for valid witness when using empty output commitments", async () => {
    const inputValues = [32, 40];
    const outputValues = [72, 0];

    const salt1 = newSalt();
    const input1 = poseidonHash([
      BigInt(inputValues[0]),
      salt1,
      ...Alice.pubKey,
    ]);
    const salt2 = newSalt();
    const input2 = poseidonHash([
      BigInt(inputValues[1]),
      salt2,
      ...Alice.pubKey,
    ]);
    const inputCommitments = [input1, input2];

    const salt4 = newSalt();
    const output2 = poseidonHash([
      BigInt(outputValues[1]),
      salt4,
      ...Alice.pubKey,
    ]);
    // the first output is a "padding" empty commitment — the KYC check
    // gates its identity MTP off when the output commitment is zero.
    const outputCommitments = [0, output2];

    const proofAlice = await smtKYC.generateCircomVerifierProof(
      poseidonHash2(Alice.pubKey),
      ZERO_HASH,
    );
    const proofBob = await smtKYC.generateCircomVerifierProof(
      poseidonHash2(Bob.pubKey),
      ZERO_HASH,
    );
    const identitiesRoot = proofAlice.root.bigInt();

    const witness = await circuit.calculateWitness(
      {
        inputCommitments,
        inputValues,
        inputSalts: [salt1, salt2],
        inputOwnerPrivateKey: senderPrivateKey,
        identitiesRoot,
        identitiesMerkleProof: [
          proofAlice.siblings.map((s) => s.bigInt()),
          proofBob.siblings.map((s) => s.bigInt()),
          proofAlice.siblings.map((s) => s.bigInt()),
        ],
        outputCommitments,
        outputValues,
        outputSalts: [0, salt4],
        outputOwnerPublicKeys: [Bob.pubKey, Alice.pubKey],
      },
      true,
    );

    expect(witness[1]).to.equal(BigInt(inputCommitments[0]));
    expect(witness[2]).to.equal(BigInt(inputCommitments[1]));
    expect(witness[3]).to.equal(identitiesRoot);
    expect(witness[4]).to.equal(0n);
    expect(witness[5]).to.equal(BigInt(outputCommitments[1]));
  });

  it("should fail if not using the right identities merkle proofs", async () => {
    const inputValues = [32, 40];
    const outputValues = [20, 52];

    const salt1 = newSalt();
    const input1 = poseidonHash([
      BigInt(inputValues[0]),
      salt1,
      ...Alice.pubKey,
    ]);
    const salt2 = newSalt();
    const input2 = poseidonHash([
      BigInt(inputValues[1]),
      salt2,
      ...Alice.pubKey,
    ]);
    const inputCommitments = [input1, input2];

    const salt3 = newSalt();
    const output1 = poseidonHash([
      BigInt(outputValues[0]),
      salt3,
      ...Bob.pubKey,
    ]);
    const salt4 = newSalt();
    const output2 = poseidonHash([
      BigInt(outputValues[1]),
      salt4,
      ...Alice.pubKey,
    ]);
    const outputCommitments = [output1, output2];

    const proofAlice = await smtKYC.generateCircomVerifierProof(
      poseidonHash2(Alice.pubKey),
      ZERO_HASH,
    );
    const proofBob = await smtKYC.generateCircomVerifierProof(
      poseidonHash2(Bob.pubKey),
      ZERO_HASH,
    );
    const identitiesRoot = proofAlice.root.bigInt();

    let error;
    try {
      await circuit.calculateWitness(
        {
          inputCommitments,
          inputValues,
          inputSalts: [salt1, salt2],
          inputOwnerPrivateKey: senderPrivateKey,
          identitiesRoot,
          identitiesMerkleProof: [
            proofAlice.siblings.map((s) => s.bigInt()),
            proofBob.siblings.map((s) => s.bigInt()),
            [0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n], // invalid MTP for the 2nd output owner
          ],
          outputCommitments,
          outputValues,
          outputSalts: [salt3, salt4],
          outputOwnerPublicKeys: [Bob.pubKey, Alice.pubKey],
        },
        true,
      );
    } catch (e) {
      error = e;
    }
    expect(error).to.match(/Error in template CheckSMTProof/);
  });

  it("should fail if input and output values do not balance", async () => {
    const inputValues = [32, 40];
    // 30 + 50 = 80 != 32 + 40 = 72  →  CheckSum should reject.
    const outputValues = [30, 50];

    const salt1 = newSalt();
    const input1 = poseidonHash([
      BigInt(inputValues[0]),
      salt1,
      ...Alice.pubKey,
    ]);
    const salt2 = newSalt();
    const input2 = poseidonHash([
      BigInt(inputValues[1]),
      salt2,
      ...Alice.pubKey,
    ]);
    const inputCommitments = [input1, input2];

    const salt3 = newSalt();
    const output1 = poseidonHash([
      BigInt(outputValues[0]),
      salt3,
      ...Bob.pubKey,
    ]);
    const salt4 = newSalt();
    const output2 = poseidonHash([
      BigInt(outputValues[1]),
      salt4,
      ...Alice.pubKey,
    ]);
    const outputCommitments = [output1, output2];

    const proofAlice = await smtKYC.generateCircomVerifierProof(
      poseidonHash2(Alice.pubKey),
      ZERO_HASH,
    );
    const proofBob = await smtKYC.generateCircomVerifierProof(
      poseidonHash2(Bob.pubKey),
      ZERO_HASH,
    );
    const identitiesRoot = proofAlice.root.bigInt();

    let error;
    try {
      await circuit.calculateWitness(
        {
          inputCommitments,
          inputValues,
          inputSalts: [salt1, salt2],
          inputOwnerPrivateKey: senderPrivateKey,
          identitiesRoot,
          identitiesMerkleProof: [
            proofAlice.siblings.map((s) => s.bigInt()),
            proofBob.siblings.map((s) => s.bigInt()),
            proofAlice.siblings.map((s) => s.bigInt()),
          ],
          outputCommitments,
          outputValues,
          outputSalts: [salt3, salt4],
          outputOwnerPublicKeys: [Bob.pubKey, Alice.pubKey],
        },
        true,
      );
    } catch (e) {
      error = e;
    }
    expect(error).to.match(/Error in template CheckSum/);
  });
});
