**UTXO**

: Unspent Transaction Output. First pioneered by the Bitcoin network, the UTXO state model uses individual tokens similar to coins to represent states. Instead of maintaining a per-account state (such as ERC20 balances) as is in the account model, which is the other significant state model, UTXO states are independent to each other. Each UTXO defines its own spending rules that must be satisfied in order to spend.

**Commitment**

: Every UTXO state maintained by the Zeto smart contract is a representation of the secrets (value, ownership) behind the token. The form of representation is a secure cryptographic hash of the secrets. This is formally called a commitment because it "locks down" the secrets. Any attempts to change the secrets such as the value or the ownership of a token will result in a different hash. These commitments are critical in verifying ZKPs to process transactions.

**Nullifier**

: It's a special type of hash that is securely, and secretly, bound to an UTXO. It's sole purpose is to demonstrate that a UTXO has been spent, although which particular UTXO is known only to the owner. Only the owner of an UTXO can produce the proper nullifier for the UTXO, which can be proven with a ZKP. Nullifiers are used when history masking is required, so that no one other than the owner of a UTXO can find out which UTXO have been spent by a transaction.

**Lock**

: A mechanism that pins one or more UTXOs under a unique `lockId`, restricting who can authorize their consumption. Locks follow the `ILockableCapability` interface lifecycle: `createLock`, `updateLock`, `delegateLock`, `spendLock`, and `cancelLock`. See [Locks for multi-step trade flows](../advanced/locks.md) for details.

**Spender**

: The Ethereum address currently authorized to spend, cancel, or delegate a lock. When a lock is created, the creator is both the owner and the spender. After `delegateLock`, only the designated spender can act on the lock.
