# Zeto - UTXO based privacy-preserving token toolkit using Zero-Knowledge Proofs

Zeto implements several practical smart contracts on EVM for privacy-preserving fungible and non-fungible tokens that achieve the following security properties, enforced with zero-knowledge proofs:

- **Anonymity** of sender and receiver
- **Encrypted secrets** stored within transactions
- **History masking**
- **KYC** (know your customer)
- **Non-repudiation** with respect to a trusted auditing authority, specified at contract-creation time

We provide a variety of token implementations that achieve targeted subsets of these properties. Each token is provided in two variants: one which accepts 2 input UTXOs and 2 output UTXOs per transaction, and a corresponding `_batch` version accepting 10 inputs and outputs per transaction, albeit with higher ZKP overhead.

Refer to the [Zeto website](https://hyperledger-labs.github.io/zeto/head/) for more information.

# Subprojects

There are 4 subprojects. Navigate to each subproject to run the tests and learn how to use each library:

- [Javascript library for proof generation](./zkp/js/): For getting started, **build this first.** This library pre-compiles all included circuits, and initializes ZK proof secrets _for testing purposes only._
- [ZKP circuits](./zkp/circuits/): Core zero-knowledge proofs for enforcing the required security goals.
- [Zeto token implementations in Solidity](./solidity/): Solidity contracts for all ZKP-based Zeto privacy patterns, including examples of deployment in a test environment.
- [Golang SDK](./go-sdk/): An interface to interact with Zeto tokens in golang. This includes a Sparse Merkle Tree implementation, Babyjubjub key manipulations, and proof generation via compiled circom circuits in WASM format.

# How to use

If the provided token implementations satisfy your requirements, they can be deployed as-is. They can also be modified and used as templates for implementations which achieve different combinations of security goals.

**Warning:** We provide a testing framework for Zeto tokens, which initializes the zero-knowledge proof infrastructure locally. This is not sufficient to establish trust in the generated proofs! For deployment, the proving keys **must** be generated either in a well-documented, decentralized ceremony, or by one trusted, central party. Refer to the [snarkjs documentation](https://github.com/iden3/snarkjs) for details on how to conduct this ceremony.

## Related projects

[Paladin](https://github.com/LF-Decentralized-Trust-labs/paladin) is the recommended client runtime for Zeto tokens. It includes capabilities for indexing Zeto UTXOs (including tracking them in a client-side Sparse Merkle Tree) and submitting transactions against a Zeto token contract. It also provides infrastructure for key management and private data stores.
