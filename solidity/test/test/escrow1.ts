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
import zkEscrowModule from "../../ignition/modules/test/escrow1";
import { prepareProof } from "../lib/anon_zeto_helpers";
import {
  UTXO,
  User,
  newUser,
  newUTXO,
  doMint,
  ZERO_UTXO,
  logger,
} from "../lib/utils";
import { loadProvingKeys } from "../utils";
import { deployZeto } from "../lib/deploy";

// ABI fragments for the ZetoLockableCapability *Args payloads.
// These mirror the canonical encodings used by every Zeto token that
// implements ILockableCapability.
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

describe("Escrow flow for payment with Zeto_Anon", function () {
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
  let circuit: any;
  let provingKey: string;
  let paymentId: any;

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

    // The Zeto_Anon token uses the same `anon` circuit for both regular
    // transfers and the locked-input branch (the lockVerifier is wired
    // to Groth16Verifier_Anon in the ignition module). One circuit/key
    // pair therefore covers both the createLock and spendLock proofs.
    circuit = await loadCircuit("anon");
    ({ provingKeyFile: provingKey } = loadProvingKeys("anon"));

    ({ deployer, zeto: zkPayment } = await deployZeto("Zeto_Anon"));
    logger.debug(`ZK Payment contract deployed at ${zkPayment.target}`);
    ({ zkEscrow } = await ignition.deploy(zkEscrowModule, {
      parameters: {
        zkEscrow1: {
          paymentToken: zkPayment.target,
        },
      },
    }));
  });

  it("mint to Alice some payment tokens", async function () {
    payment1 = newUTXO(10, Alice);
    payment2 = newUTXO(20, Alice);
    const result = await doMint(zkPayment, deployer, [payment1, payment2]);

    // simulate Alice and Bob listening to minting events and updating
    // their local merkle trees
    for (const log of result.logs) {
      const event = zkPayment.interface.parseLog(log as any);
      expect(event.args.outputs.length).to.equal(2);
    }
  });

  it("Alice locks payment1 by calling createLock on the Zeto token", async function () {
    // The locked output preserves the value but is a fresh commitment
    // (new salt). The createLock proof attests to the standard transfer
    // payment1 -> lockedPayment1.
    lockedPayment1 = newUTXO(payment1.value!, Alice);
    const encodedZkProof = await prepareProof(
      circuit,
      provingKey,
      Alice,
      [payment1, ZERO_UTXO],
      [lockedPayment1, ZERO_UTXO],
      [Alice, {}],
    );

    const createArgs = encodeCreateArgs({
      txId: randomBytes32(),
      inputs: [payment1.hash],
      // For the fungible Zeto_Anon createLock, lockedOutputs holds the
      // freshly-locked UTXO and outputs is empty (no change is being
      // returned to Alice, since payment1's full value is moved into
      // the lock).
      outputs: [],
      lockedOutputs: [lockedPayment1.hash],
      proof: encodeProofOnly(encodedZkProof),
    });

    // Pre-compute the lockId off-chain to assert the contract derives
    // the same value (deterministic from caller + txId).
    lockId = await zkPayment.connect(Alice.signer).computeLockId(createArgs);

    const tx = await zkPayment
      .connect(Alice.signer)
      .createLock(createArgs, ethers.ZeroHash, ethers.ZeroHash, "0x");
    const result: ContractTransactionReceipt | null = await tx.wait();
    logger.debug(`createLock() complete. Gas used: ${result?.gasUsed}`);

    // Sanity-check the lock state after creation.
    const info = await zkPayment.getLock(lockId);
    expect(info.owner).to.equal(Alice.ethAddress);
    expect(info.spender).to.equal(Alice.ethAddress);
    expect(await zkPayment.locked(lockedPayment1.hash)).to.deep.equal([
      true,
      Alice.ethAddress,
    ]);
  });

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

    // After delegation the escrow is the sole spender; Alice can no
    // longer spend the lock directly.
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

    // Bob listens to the payment events and verifies the proposed
    // payment matches what Alice promised off-chain.
    expect(initiated!.outputs[0]).to.equal(paymentToBob.hash);
    expect(initiated!.lockId).to.equal(lockId);
    paymentId = initiated!.paymentId;
  });

  it("Alice approves the payment by submitting a valid locked-input proof", async function () {
    // The spend proof transfers lockedPayment1 -> paymentToBob (now
    // owned by Bob). Same `anon` circuit as the createLock step.
    const encodedZkProof = await prepareProof(
      circuit,
      provingKey,
      Alice,
      [lockedPayment1, ZERO_UTXO],
      [paymentToBob, ZERO_UTXO],
      [Bob, {}],
    );
    const tx = await zkEscrow
      .connect(Alice.signer)
      .approvePayment(paymentId, encodeProofOnly(encodedZkProof), "0x");
    const result = await tx.wait();

    // Bob listens to the escrow's PaymentApproved event; the escrow
    // having stored the proof guarantees completePayment cannot fail
    // on proof grounds later.
    const approved = parseEscrowEvent(zkEscrow, result, "PaymentApproved");
    expect(approved, "PaymentApproved event not emitted").to.not.be.undefined;
    expect(approved!.paymentId).to.equal(paymentId);
  });

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

    // Lock is consumed; the locked-UTXO ledger no longer carries
    // lockedPayment1.
    expect(await zkPayment.isLockActive(lockId)).to.equal(false);
    expect((await zkPayment.locked(lockedPayment1.hash))[0]).to.be.false;

    // Escrow's PaymentCompleted event fires for the same paymentId.
    const completed = parseEscrowEvent(zkEscrow, result, "PaymentCompleted");
    expect(completed, "PaymentCompleted event not emitted").to.not.be.undefined;
    expect(completed!.paymentId).to.equal(paymentId);
  });
});

// parseEscrowEvent extracts the first event of a given name from a
// transaction receipt by parsing logs through the escrow contract's
// own ABI. Unlike `parseUTXOEvents`, which only knows about the Zeto
// token's UTXO event family, this helper handles the escrow's
// custom Payment* events.
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
      // Return the args Result directly; ethers exposes named fields
      // (e.g. result.paymentId) alongside positional ones.
      return parsed.args;
    }
  }
  return undefined;
}

// encodeProofOnly mirrors the wire format that
// {Zeto_Anon.constructPublicInputs} expects: a bare `Commonlib.Proof`
// tuple (no merkle root prefix, since Zeto_Anon is non-nullifier).
function encodeProofOnly(proof: any) {
  return new AbiCoder().encode(
    ["tuple(uint256[2] pA, uint256[2][2] pB, uint256[2] pC)"],
    [proof],
  );
}
