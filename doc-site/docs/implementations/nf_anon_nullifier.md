# Zeto_NfAnonNullifier

| Anonymity          | History Masking    | Locking            | Encryption | KYC | Non-repudiation | Gas Cost (estimate) |
| ------------------ | ------------------ | ------------------ | ---------- | --- | --------------- | ------------------- |
| :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | -          | -   | -               | 1,450,258           |

This implements a non-fungible token using nullifiers, thus hiding the spending graph.

The statements in the proof include:

- the output UTXO hashes are based on the same id, uri as the input UTXO hashes
- the sender possesses the private BabyJubjub key, whose public key is part of the pre-image of the input commitment hashes, which match the corresponding nullifiers
- the nullifiers represent input commitments that are included in a Sparse Merkle Tree represented by the root hash
