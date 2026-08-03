# Zeto_Anon

| Anonymity          | History Masking | Locking            | Encryption | KYC | Non-repudiation | Gas Cost (estimate) |
| ------------------ | --------------- | ------------------ | ---------- | --- | --------------- | ------------------- |
| :heavy_check_mark: | -               | :heavy_check_mark: | -          | -   | -               | 326,583             |

This is the simplest version of the ZKP circuit. Because the secrets required to open the commitment hashes, namely the output UTXO value and salt, are NOT published as part of the transaction payload, using this version requires the secrets to be transmitted from the sender to the receiver in off-chain channels.

The statements in the proof include:

- each value in the output commitments must be a positive number in the range 0 ~ (2\*\*40 - 1)
- the sum of the input values match the sum of output values
- the hashes in the input and output match the hash(value, salt, owner public key) formula
- the sender possesses the private BabyJubjub key, whose public key is part of the pre-image of the input commitment hashes

There is no history masking, meaning the associations between the consumed input UTXOs and the output UTXOs are in the clear.

[![wiring_anon](../images/circuit_wiring_anon.jpg)](../images/circuit_wiring_anon.jpg)
