# Zeto_AnonEncNullifierNonRepudiation

| Anonymity          | History Masking    | Locking            | Encryption         | KYC | Non-repudiation    | Gas Cost (estimate) |
| ------------------ | ------------------ | ------------------ | ------------------ | --- | ------------------ | ------------------- |
| :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | -   | :heavy_check_mark: | 2,763,071           |

The concept of "non-repudiation" is introduced in this implementation pattern.

Since all onchain states are hashes, with ownership information for the assets hidden, it's possible that a participant can send a transaction but subsequently deny it. Because the transaction signer account no longer reflects the identity of the asset owner, as discussed above, it will be impossible to know who was the sender of a transaction from purely looking at the onchain data, which is exactly the point for Zeto's anonymity support. This gives a malicious party the ability to gain repudiation, or deny that they were responsible for a past transaction.

This implementation pattern addresses that concern by encrypting the ownership information of each UTXO involved in a transaction with an authority's registered key. Only the designated authority will be able to decrypt the ownership information. The encryption is performed inside the ZKP circuit, thus guaranteeing that they are the actual owners of the UTXOs.

The statements in the proof include:

- each value in the output commitments must be a positive number in the range 0 ~ (2\*\*100 - 1)
- the sum of the nullified values match the sum of output values
- the hashes in the output match the hash(value, salt, owner public key) formula
- the sender possesses the private BabyJubjub key, whose public key is part of the pre-image of the input commitment hashes, which match the corresponding nullifiers
- the nullifiers represent input commitments that are included in a Sparse Merkle Tree represented by the root hash
- the encrypted values in the transaction contains cipher texts derived from the receiver's UTXO values and encrypted with a shared secret using the ECDH protocol between a random private key and the receiver (this guarantees data availability for the receiver, because the public key for the random private key used by the sender is published in the transaction)
- the encrypted values in the transaction contains cipher texts derived from the receiver's UTXO values and encrypted with a shared secret using the ECDH protocol between a random private key and the authority's public key
