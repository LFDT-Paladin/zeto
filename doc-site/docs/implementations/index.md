# Overview of Zeto Token Implementations

Zeto is not a single privacy-preserving token implementation. It's a collection of implementations that meet a wide range of requirements in different use cases. The collection will continue to grow as new patterns are implemented.

Below is a summary and comparison table among the current list of implementations.

| Fungible Token Implementation       | Anonymity          | History Masking    | Locking            | Encryption         | KYC                | Non-repudiation    | Gas Cost (estimate) |
| ----------------------------------- | ------------------ | ------------------ | ------------------ | ------------------ | ------------------ | ------------------ | ------------------- |
| Zeto_Anon                           | :heavy_check_mark: | -                  | :heavy_check_mark: | -                  | -                  | -                  | 326,583             |
| Zeto_AnonNullifier                  | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | -                  | -                  | -                  | 2,005,587           |
| Zeto_AnonEnc                        | :heavy_check_mark: | -                  | :heavy_check_mark: | :heavy_check_mark: | -                  | -                  | 425,338             |
| Zeto_AnonEncNullifier               | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | -                  | -                  | 2,472,994           |
| Zeto_AnonNullifierKyc               | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | -                  | :heavy_check_mark: | -                  | 2,310,424           |
| Zeto_AnonEncNullifierKyc            | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | -                  | 2,414,345           |
| Zeto_AnonEncNullifierNonRepudiation | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | -                  | :heavy_check_mark: | 2,763,071           |
| Zeto_AnonNullifierQurrency          | :heavy_check_mark: | :heavy_check_mark: | :soon:             | :heavy_check_mark: | -                  | -                  | 2,066,430           |

| Non-Fungible Token Implementation | Anonymity          | History Masking    | Locking            | Encryption | KYC | Non-repudiation | Gas Cost (estimate) |
| --------------------------------- | ------------------ | ------------------ | ------------------ | ---------- | --- | --------------- | ------------------- |
| Zeto_NfAnon                       | :heavy_check_mark: | -                  | :heavy_check_mark: | -          | -   | -               | 271,890             |
| Zeto_NfAnonNullifier              | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | -          | -   | -               | 1,450,258           |

The various patterns in this project use Zero Knowledge Proofs (ZKP) to demonstrate the validity of the proposed transaction. There is no centralized party to trust as in the Notary pattern, which is not implemented in this project but [in the Paladin project](https://lf-decentralized-trust-labs.github.io/paladin/head/concepts/tokens/).

Using ZKPs as validity proofs, each participant can independently submit transactions to the smart contract directly. As long as the participant is able to produce a valid proof, the transaction will be successfully verified and allowed to go through.

Lockable token implementations share the `ILockableCapability` interface with [Paladin](https://lf-decentralized-trust-labs.github.io/paladin/head/concepts/tokens/), providing a consistent lock/delegate/spend/cancel lifecycle across privacy token types. See [Locks for multi-step trade flows](../advanced/locks.md) for details.

This project includes multiple ZKP circuits to support various privacy levels with Zeto.
