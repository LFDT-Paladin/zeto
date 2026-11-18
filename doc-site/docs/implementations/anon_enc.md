# Zeto_AnonEnc

| Anonymity          | History Masking | Locking            | Encryption         | KYC | Non-repudiation | Gas Cost (estimate) |
| ------------------ | --------------- | ------------------ | ------------------ | --- | --------------- | ------------------- |
| :heavy_check_mark: | -               | :heavy_check_mark: | :heavy_check_mark: | -   | -               | 425,338             |

This version of the ZKP circuit adds encryption that makes it possible to provide data availability onchain. The circuit uses the sender's private key and the receiver's public key to generate a shared secret with ECDH, which guarantees that the receiver will be able to decrypt the values. The encrypted values include the value and salt of the output UTXO for the receiver. With these values the receiver is guaranteed to be able to spend the UTXO sent to them.

The statements in the proof include:

- each value in the output commitments must be a positive number in the range 0 ~ (2\*\*100 - 1)
- the sum of the input values match the sum of output values
- the hashes in the input and output match the hash(value, salt, owner public key) formula
- the sender possesses the private BabyJubjub key, whose public key is part of the pre-image of the input commitment hashes
- the encrypted values in the transaction are derived from the receiver's UTXO value and encrypted with a shared secret using the ECDH protocol between a random private key and the receiver (this guarantees data availability for the receiver, because the public key for the random private key used by the sender is published in the transaction)

There is no history masking, meaning the association between the consumed input UTXOs and the output UTXOs are in the clear.
