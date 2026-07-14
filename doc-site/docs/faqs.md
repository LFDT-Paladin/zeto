# Frequently Asked Questions

## Can I develop a self-custody wallet for Zeto tokens?

Due to the usage of UTXOs for the onchain token commitments, a "wallet" for Zeto will be architecturally similar to a Bitcoin wallet. It must index the entire chain of blocks since the deployment of the Zeto contract, in order to discover all the Zeto tokens that belong to the user. Figuring out the user's balance is achieved by adding together the values of all the UTXOs owned by the account, meaning the `owner public key` part of the commitment hash matches the user's Babyjubjub public key.

Spending Zeto tokens requires surveying the account's UTXOs and select the collection of tokens that makes the most sense for the requested amount.

Finally the wallet must be able to generate the appropriate ZK proofs for the intended transactions to send to the Zeto smart contract.

In summary, a Zeto wallet is a sophisticated software that will be more complex than typical self-custody wallets such as Metamask, which only needs to manage signing keys and make JSON-RPC calls against the target blockchain. Refer to an existing implementation of a Zeto client such as [Paladin](https://github.com/LF-Decentralized-Trust-labs/paladin) for details.

## What "SDK" should I use in my application to work with Zeto tokens?

As explained above, working with Zeto tokens requires a sophisticated client such as [Paladin](https://github.com/LF-Decentralized-Trust-labs/paladin). Even though the Zeto project provides a [go-sdk](https://github.com/LFDT-Paladin/zeto/tree/main/go-sdk), to build a robust client for Zeto is a major engineering effort. Starting with Paladin is highly recommended instead of re-implementing one from scratch.

## Why do I need Zeto tokens if I already get privacy with ZK rollups or Validium Layer 2's?

It's a common misconception that ZK rollups (Linea, zkSync, Polygon zkEVM, etc.) provides privacy. As of this writing, all the ZK rollups except Aztec use Zero Knowledge Proofs for scalability rather than privacy. All the transaction data are public information in two contexts:

- the L2 network is a transparent shared ledger, where all the transactions are broadcast to all the L2 nodes
- all the L2 transaction data are sent to the verifier contract in L1

Due to the above two aspects, ZK rollups provides no privacy over L2 transactions.

What about [Validium L2's](https://ethereum.org/en/developers/docs/scaling/validium/)? They send hashes of the L2 transactions rather than the transaction data to L1, and uses DAC's (Data Availability Committees) to manage the transaction data. Even though there is no information exposure to L1, there is still no privacy due to the follow two aspects:

- the L2 network is a transparent shared ledger, where all the transactions are broadcast to all the L2 nodes
- the DAC must make all the transaction data available to anyone who wants to ask for it, in order for a L2 user to generate a merkle proof to withdraw their assets from the Validium network's L1 contract

In summary, even if a L2 network uses ZKP, there is no privacy over the transactions that are sent to the L2 network.

## How is Zeto different than Aztec?

As mentioned above, [Aztec](https://docs.aztec.network/) is a rollup L2 that offers privacy at the protocol level. Zeto shares some common designs with Aztec:

- UTXOs: both Zeto and Aztec use UTXOs (Unspent Transaction Outputs) as the onchain state model
- private storage: client maintains private storage that persists secrets belonging to a user
- ZKP: zero knowledge proofs are used to ensure transactions are honestly constructed and state transitions are correct

On the other hand, there are significant differences:

- target EVM: Zeto is implemented on top of a vanilla EVM, making it compatible with any EVM blockchain including both L1's and L2's. On the other hand, Aztec is an L2 protocol and relies on a specialized EVM. So far Zeto has been tested on multiple EVM based L1 and L2 blockchains:
  - Ethereum
  - Polygon
  - Linea
  - Arbitrum
- ZK circuit design language: Zeto currently uses [circom](https://github.com/iden3/circomlib) which is the most widely used DSL for designing ZK circuits, and most widely supported by the different proving systems (groth16, plonk, fflonk, nova). To develop ZK circuits for Aztec, you use [Noir](https://noir-lang.org/docs).
