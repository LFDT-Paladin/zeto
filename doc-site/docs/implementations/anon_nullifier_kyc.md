# Zeto_AnonNullifierKyc

| Anonymity          | History Masking    | Locking            | Encryption | KYC                | Non-repudiation | Gas Cost (estimate) |
| ------------------ | ------------------ | ------------------ | ---------- | ------------------ | --------------- | ------------------- |
| :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | -          | :heavy_check_mark: | -               | 2,310,424           |

The concept of "KYC with privacy" is introduced in this implementation pattern.

How to enforce a policy of "all senders and receivers of a transaction must be in a KYC registry", while maintaining anomymity of the sender and the receiver? The solution is similar to how nullifiers are supported, via merkle tree proofs.

The implementation of this pattern maintains a KYC registry in the smart contract as a Sparse Merkle Tree. The registry is maintained by a designated authority, and includes the public keys of entities that have cleared the KYC process. Each transaction must demonstrate that the public keys of the sender and the receivers are included in the KYC merkle tree, by generating a merkle proof and using it as a private input to the ZKP circuit.

The statements in the proof include:

- each value in the output commitments must be a positive number in the range 0 ~ (2\*\*100 - 1)
- the sum of the nullified values match the sum of output values
- the hashes in the output match the hash(value, salt, owner public key) formula
- the sender possesses the private BabyJubjub key, whose public key is part of the pre-image of the input commitment hashes, which match the corresponding nullifiers
- the nullifiers represent input commitments that are included in a Sparse Merkle Tree represented by the root hash
- the sender and receiver public keys are included in the Sparse Merkle Tree for the KYC registry, represented by the latest root hash known to the smart contract
