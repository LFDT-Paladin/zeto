# Zeto_NfAnon

| Anonymity          | History Masking | Locking            | Encryption | KYC | Non-repudiation | Gas Cost (estimate) |
| ------------------ | --------------- | ------------------ | ---------- | --- | --------------- | ------------------- |
| :heavy_check_mark: | -               | :heavy_check_mark: | -          | -   | -               | 271,890             |

This implements a basic non-fungible token.

For non-fungible tokens, the main concern with the transaction validity check is that the output UTXO contains the same secrets (id, uri) as the input UTXO, with only the ownership updated.

The statements in the proof include:

- the output UTXO hashes are based on the same id, uri as the input UTXO hashes
- the sender possesses the private BabyJubjub key, whose public key is part of the pre-image of the input commitment hashes
