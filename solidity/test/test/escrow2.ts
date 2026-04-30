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

import { ethers, ignition, network } from "hardhat";
import {
  Signer,
  AbiCoder,
  BigNumberish,
  ContractTransactionReceipt,
} from "ethers";
import { expect } from "chai";
import { loadCircuit } from "zeto-js";
import { Merkletree, InMemoryDB, str2Bytes } from "@iden3/js-merkletree";
import zkEscrowModule from "../../ignition/modules/test/escrow2";
import { prepareProof as prepareNullifierUnlockedProof } from "../lib/anon_nullifier_helpers";
// The locked-input transition for Zeto_AnonNullifier reuses the simple
// `anon` circuit (the lockVerifier in the ignition module is wired to
// {Groth16Verifier_Anon}, mirroring what the production ZK proof path
// expects from {ZetoFungible._transferLocked}). So the spend proof for
// the escrow flow is built with `prepareProof` from {anon_zeto_helpers}
// (same circuit helper as in `zeto_anon.ts`), not from the nullifier suite.
import { prepareProof as prepareProofAnonCircuit } from "../lib/anon_zeto_helpers";
import {
  UTXO,
  User,
  newUser,
  newUTXO,
  newNullifier,
  doMint,
  ZERO_UTXO,
  logger,
} from "../lib/utils";
import { loadProvingKeys } from "../utils";
import { deployZeto } from "../lib/deploy";

// ABI fragments mirror the canonical ZetoLockableCapability *Args
// payloads used uniformly across all Zeto tokens.
const CREATE_ARGS_ABI =
  "tuple(bytes32 txId, uint256[] inputs, uint256[] outputs, uint256[] lockedOutputs, bytes proof)";
const DELEGATE_ARGS_ABI = "tuple(bytes32 txId)";

function encodeCreateArgs(args: {
  txId: string;
  inputs: BigNumberish[];
  outputs: BigNumberish[];
  lockedOutputs: BigNumberish[];
  proof: string;
}) {
  return new AbiCoder().encode([CREATE_ARGS_ABI], [args]);
}

function encodeDelegateArgs(txId: string) {
  return new AbiCoder().encode([DELEGATE_ARGS_ABI], [{ txId }]);
}

function randomBytes32(): string {
  return ethers.hexlify(ethers.randomBytes(32));
}

describe("Escrow flow for payment with Zeto_AnonNullifier", function () {
  let Alice: User;
  let Bob: User;
  let Charlie: User;

  // instances of the contracts
  let zkPayment: any;
  let zkEscrow: any;

  // payment UTXOs to be minted and transferred
  let payment1: UTXO;
  let payment2: UTXO;

  // UTXOs involved in the escrow flow
  let lockedPayment1: UTXO;
  let paymentToBob: UTXO;
  let lockId: string;

  // other variables
  let deployer: Signer;
  // unlocked-input transfer circuit (nullifier + merkle proof)
  let circuit: any;
  let provingKey: string;
  // locked-input transfer circuit (simpler `anon`, no nullifier or root)
  let circuitLocked: any;
  let provingKeyLocked: string;
  let paymentId: any;
  let smtAlice: Merkletree;

  before(async function () {
    if (network.name !== "hardhat") {
      this.timeout(120000);
    }
    let [d, a, b, c] = await ethers.getSigners();
    deployer = d;
    Alice = await newUser(a);
    Bob = await newUser(b);
    Charlie = await newUser(c);

    circuit = await loadCircuit("anon_nullifier_transfer");
    ({ provingKeyFile: provingKey } = loadProvingKeys(
      "anon_nullifier_transfer",
    ));
    circuitLocked = await loadCircuit("anon");
    ({ provingKeyFile: provingKeyLocked } = loadProvingKeys("anon"));

    const storage1 = new InMemoryDB(str2Bytes(""));
    smtAlice = new Merkletree(storage1, true, 64);

    ({ deployer, zeto: zkPayment } = await deployZeto("Zeto_AnonNullifier"));
    logger.debug(`ZK Payment contract deployed at ${zkPayment.target}`);
    ({ zkEscrow } = await ignition.deploy(zkEscrowModule, {
      parameters: {
        zkEscrow2: {
          paymentToken: zkPayment.target,
        },
      },
    }));
  });

  it("mint to Alice some payment tokens", async function () {
    payment1 = newUTXO(10, Alice);
    payment2 = newUTXO(20, Alice);
    const result = await doMint(zkPayment, deployer, [payment1, payment2]);

    for (const log of result.logs) {
      const event = zkPayment.interface.parseLog(log as any);
      expect(event.args.outputs.length).to.equal(2);
    }

    // Mirror the on-chain unlocked-commitments SMT off-chain so we can
    // build merkle proofs for the unlocked-input transition that
    // creates the lock.
    await smtAlice.add(payment1.hash, payment1.hash);
    await smtAlice.add(payment2.hash, payment2.hash);
  });

  it("Alice locks payment1 by calling createLock on the Zeto token", async function () {
    // Alice generates the nullifier for payment1 and a merkle inclusion
    // proof in the unlocked-commitments SMT.
    const nullifier1 = newNullifier(payment1, Alice);
    const root = await smtAlice.root();
    const p1 = await smtAlice.generateCircomVerifierProof(payment1.hash, root);
    const p2 = await smtAlice.generateCircomVerifierProof(0n, root);
    const merkleProofs = [
      p1.siblings.map((s) => s.bigInt()),
      p2.siblings.map((s) => s.bigInt()),
    ];

    lockedPayment1 = newUTXO(payment1.value!, Alice);
    const encodedZkProof = await prepareNullifierUnlockedProof(
      circuit,
      provingKey,
      Alice,
      [payment1, ZERO_UTXO],
      [nullifier1, ZERO_UTXO],
      [lockedPayment1, ZERO_UTXO],
      root.bigInt(),
      merkleProofs,
      [Alice, Alice],
    );

    const createArgs = encodeCreateArgs({
      txId: randomBytes32(),
      inputs: [nullifier1.hash],
      // For Zeto_AnonNullifier createLock, lockedOutputs holds the
      // freshly-locked UTXO and outputs is empty; payment1's full value
      // moves into the lock.
      outputs: [],
      lockedOutputs: [lockedPayment1.hash],
      proof: encodeUnlockedProof(root.bigInt(), encodedZkProof),
    });

    lockId = await zkPayment.connect(Alice.signer).computeLockId(createArgs);

    const tx = await zkPayment
      .connect(Alice.signer)
      .createLock(createArgs, ethers.ZeroHash, ethers.ZeroHash, "0x");
    const result = await tx.wait();
    logger.debug(`createLock() complete. Gas used: ${result?.gasUsed}`);

    const info = await zkPayment.getLock(lockId);
    expect(info.owner).to.equal(Alice.ethAddress);
    expect(info.spender).to.equal(Alice.ethAddress);
    expect(await zkPayment.locked(lockedPayment1.hash)).to.deep.equal([
      true,
      Alice.ethAddress,
    ]);
  }).timeout(120000);

  it("Alice delegates the lock to the escrow contract", async function () {
    const tx = await zkPayment
      .connect(Alice.signer)
      .delegateLock(
        lockId,
        encodeDelegateArgs(randomBytes32()),
        zkEscrow.target,
        "0x",
      );
    await tx.wait();

    const info = await zkPayment.getLock(lockId);
    expect(info.spender).to.equal(zkEscrow.target);
    expect(await zkPayment.locked(lockedPayment1.hash)).to.deep.equal([
      true,
      zkEscrow.target,
    ]);
  });

  it("Alice initiates a payment transaction to Bob through the escrow", async function () {
    paymentToBob = newUTXO(lockedPayment1.value!, Bob);
    const tx = await zkEscrow
      .connect(Alice.signer)
      .initiatePayment(lockId, [paymentToBob.hash], "0x");
    const result = await tx.wait();
    const initiated = parseEscrowEvent(zkEscrow, result, "PaymentInitiated");
    expect(initiated, "PaymentInitiated event not emitted").to.not.be.undefined;
    expect(initiated!.outputs[0]).to.equal(paymentToBob.hash);
    expect(initiated!.lockId).to.equal(lockId);
    paymentId = initiated!.paymentId;
  });

  it("Alice approves the payment by submitting a valid locked-input proof", async function () {
    // The locked-input transition uses the simple `anon` circuit and
    // operates on the raw UTXO hash (lockedPayment1.hash), not on a
    // nullifier. The Zeto storage layer has already validated the
    // input is in the locked-UTXO ledger.
    const encodedZkProof = await prepareProofAnonCircuit(
      circuitLocked,
      provingKeyLocked,
      Alice,
      [lockedPayment1, ZERO_UTXO],
      [paymentToBob, ZERO_UTXO],
      [Bob, {}],
    );
    const tx = await zkEscrow
      .connect(Alice.signer)
      .approvePayment(paymentId, encodeLockedProof(encodedZkProof), "0x");
    const result = await tx.wait();

    const approved = parseEscrowEvent(zkEscrow, result, "PaymentApproved");
    expect(approved, "PaymentApproved event not emitted").to.not.be.undefined;
    expect(approved!.paymentId).to.equal(paymentId);
  }).timeout(120000);

  it("Bob, or anyone, can call the escrow to finalize the payment and receive the unlocked UTXO", async function () {
    const tx = await zkEscrow
      .connect(Bob.signer)
      .completePayment(paymentId, "0x");
    const result = await tx.wait();

    // The Zeto token emits ZetoLockSpent containing the new unlocked
    // outputs.
    const lockSpent = result!.logs
      .map((l) => {
        try {
          return zkPayment.interface.parseLog(l as any);
        } catch (_e) {
          return null;
        }
      })
      .find((p: any) => p && p.name === "ZetoLockSpent");
    expect(lockSpent, "ZetoLockSpent event not emitted").to.not.be.undefined;
    expect(lockSpent!.args.outputs[0]).to.equal(paymentToBob.hash);

    expect(await zkPayment.isLockActive(lockId)).to.equal(false);
    expect((await zkPayment.locked(lockedPayment1.hash))[0]).to.be.false;

    const completed = parseEscrowEvent(zkEscrow, result, "PaymentCompleted");
    expect(completed, "PaymentCompleted event not emitted").to.not.be.undefined;
    expect(completed!.paymentId).to.equal(paymentId);
  });
});

// encodeUnlockedProof matches the wire format consumed by
// {Zeto_AnonNullifier.constructPublicInputs} on the unlocked branch:
// `(uint256 root, Commonlib.Proof)`. Used for the createLock proof.
function encodeUnlockedProof(root: any, proof: any) {
  return new AbiCoder().encode(
    ["uint256 root", "tuple(uint256[2] pA, uint256[2][2] pB, uint256[2] pC)"],
    [root, proof],
  );
}

// encodeLockedProof matches the wire format consumed on the locked
// branch: just `Commonlib.Proof`, no root prefix (the locked input is
// already vouched for by the storage layer, no merkle inclusion proof
// is needed). Used for the spendLock / approvePayment proof.
function encodeLockedProof(proof: any) {
  return new AbiCoder().encode(
    ["tuple(uint256[2] pA, uint256[2][2] pB, uint256[2] pC)"],
    [proof],
  );
}

// parseEscrowEvent extracts the first event of a given name from a
// transaction receipt by parsing logs through the escrow contract's
// own ABI. Unlike the Zeto-token-specific `parseUTXOEvents`, this
// helper handles the escrow's custom Payment* events.
function parseEscrowEvent(
  escrowContract: any,
  receipt: ContractTransactionReceipt | null,
  name: string,
): any | undefined {
  if (!receipt) return undefined;
  for (const log of receipt.logs || []) {
    let parsed;
    try {
      parsed = escrowContract.interface.parseLog(log as any);
    } catch (_e) {
      continue;
    }
    if (parsed && parsed.name === name) {
      return parsed.args;
    }
  }
  return undefined;
}
