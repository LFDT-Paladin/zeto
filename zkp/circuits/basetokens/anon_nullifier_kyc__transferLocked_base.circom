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
pragma circom 2.2.2;

include "../lib/check-positive.circom";
include "../lib/check-hashes.circom";
include "../lib/check-sum.circom";
include "../lib/kyc.circom";
include "../node_modules/circomlib/circuits/babyjub.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

// transferLocked for the KYC nullifier-based token.
//
// Under the new ILockableCapability architecture, the lockable contract
// keeps each lock's UTXOs in a flat per-lock mapping keyed by lockId
// rather than in a Sparse Merkle Tree. As a result, the locked-input
// proof no longer needs:
//   - the locked-state SMT root, per-input merkle proofs, enabled flags,
//     or lockDelegate / smtNodeValues (no SMT membership to prove);
//   - the nullifiers (the on-chain lock storage already enforces single-
//     spend semantics: a lock can only be settled once, after which the
//     locked UTXOs leave the per-lock mapping).
//
// Mirrors the structure of {transferLocked} in
// `anon_nullifier__transferLocked_base.circom`, dropping the SMT-side
// inputs. What remains is value conservation, sender-ownership, and KYC
// inclusion for the (still-original) sender plus each non-zero output
// owner.
//
// This version of the circuit performs the following operations:
// - derive the sender's public key from the sender's private key
// - check the input and output commitments match the expected hashes
// - check the input and output values sum to the same amount
// - check the owner public keys for inputs and outputs are included in
//   the identities merkle tree
template transferLocked(nInputs, nOutputs, nIdentitiesSMTLevels) {
  signal input inputCommitments[nInputs];
  signal input inputValues[nInputs];
  signal input inputSalts[nInputs];
  // must be properly hashed and trimmed to be compatible with the BabyJub curve.
  // Reference: https://github.com/iden3/circomlib/blob/master/test/babyjub.js#L103
  signal input inputOwnerPrivateKey;
  signal input identitiesRoot;
  signal input identitiesMerkleProof[nOutputs + 1][nIdentitiesSMTLevels];
  signal input outputCommitments[nOutputs];
  signal input outputValues[nOutputs];
  signal input outputOwnerPublicKeys[nOutputs][2];
  signal input outputSalts[nOutputs];

  // derive the sender's public key from the secret input
  // for the sender's private key. This step demonstrates
  // the sender really owns the private key for the input
  // UTXOs.
  var inputOwnerPubKeyAx, inputOwnerPubKeyAy;
  (inputOwnerPubKeyAx, inputOwnerPubKeyAy) = BabyPbk()(in <== inputOwnerPrivateKey);

  CheckPositive(nOutputs)(outputValues <== outputValues);

  CommitmentInputs() inAuxInputs[nInputs];
  for (var i = 0; i < nInputs; i++) {
    inAuxInputs[i].value <== inputValues[i];
    inAuxInputs[i].salt <== inputSalts[i];
    inAuxInputs[i].ownerPublicKey <== [inputOwnerPubKeyAx, inputOwnerPubKeyAy];
  }

  CommitmentInputs() outAuxInputs[nOutputs];
  for (var i = 0; i < nOutputs; i++) {
    outAuxInputs[i].value <== outputValues[i];
    outAuxInputs[i].salt <== outputSalts[i];
    outAuxInputs[i].ownerPublicKey <== outputOwnerPublicKeys[i];
  }

  CheckHashes(nInputs)(commitmentHashes <== inputCommitments, commitmentInputs <== inAuxInputs);
  CheckHashes(nOutputs)(commitmentHashes <== outputCommitments, commitmentInputs <== outAuxInputs);

  CheckSum(nInputs, nOutputs)(inputValues <== inputValues, outputValues <== outputValues);

  // Demonstrate that the owner public keys for the (still-original)
  // sender and each non-zero output owner are included in the identities
  // Sparse Merkle Tree with the root `identitiesRoot`. Zero output
  // commitments are skipped (their MTP is gated to disabled), matching
  // the unlocked KYC circuit's behavior.
  var ownerPublicKeys[nOutputs + 1][2];
  ownerPublicKeys[0] = [inputOwnerPubKeyAx, inputOwnerPubKeyAy];

  var isCommitmentZero[nOutputs];
  for (var i = 0; i < nOutputs; i++) {
    isCommitmentZero[i] = IsZero()(in <== outputCommitments[i]);
    ownerPublicKeys[i+1][0] = (1 - isCommitmentZero[i]) * outputOwnerPublicKeys[i][0];
    ownerPublicKeys[i+1][1] = (1 - isCommitmentZero[i]) * outputOwnerPublicKeys[i][1];
  }

  Kyc(nOutputs + 1, nIdentitiesSMTLevels)(publicKeys <== ownerPublicKeys, root <== identitiesRoot, merkleProof <== identitiesMerkleProof);
}
