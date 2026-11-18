# Zeto_AnonEncNullifier

| Anonymity          | History Masking    | Locking            | Encryption         | KYC | Non-repudiation | Gas Cost (estimate) |
| ------------------ | ------------------ | ------------------ | ------------------ | --- | --------------- | ------------------- |
| :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | -   | -               | 2,472,994           |

This implementation adds encryption, as described in the section above for Zeto_AnonEnc, to the pattern Zeto_AnonNullifier above.

The statements in the proof include:

- each value in the output commitments must be a positive number in the range 0 ~ (2\*\*100 - 1)
- the sum of the nullified values match the sum of output values
- the hashes in the output match the hash(value, salt, owner public key) formula
- the sender possesses the private BabyJubjub key, whose public key is part of the pre-image of the input commitment hashes, which match the corresponding nullifiers
- the nullifiers represent input commitments that are included in a Sparse Merkle Tree represented by the root hash
- the encrypted values in the transaction are derived from the receiver's UTXO value and encrypted with a shared secret using the ECDH protocol between a random private key and the receiver (this guarantees data availability for the receiver, because the public key for the random private key used by the sender is published in the transaction)
