# EIP-170 contract size (24,576 bytes)

Ethereum mainnet enforces a **24,576-byte** limit on contract **runtime bytecode** ([EIP-170](https://eips.ethereum.org/EIPS/eip-170)). Zeto builds with Hardhat using size-oriented compiler settings; oversize contracts cannot be deployed to production chains until their implementations shrink.

## Tooling

| Mechanism | Location | Behavior |
|-----------|----------|----------|
| Compiler | `hardhat.config.ts` | `optimizer.enabled`, `runs: 25`, `viaIR: true` (favors smaller bytecode) |
| `hardhat-contract-sizer` | `contractSizer.strict: true`, `runOnCompile: true` | Fails compile if any non-exempt contract exceeds 24,576 B |
| Hardhat network | `allowUnlimitedContractSize: false` | Matches mainnet: `CREATE` fails for oversize runtime code |
| Exemption list | `config/eip170.ts` | Temporary allowlist for known violators; remove entries as fixes land |

```bash
cd solidity
npm run size          # print sizes (runs compile first)
npx hardhat compile   # also runs sizer when runOnCompile is true
```

## Current status (deployed runtime bytecode)

Contracts **under** the limit include `Zeto_Anon`, `Zeto_AnonNullifier` (~219 B headroom), `Zeto_AnonEnc`, `Zeto_NfAnonNullifier`, and most Groth16 verifiers deployed as separate contracts.

### Exempt — over limit (pending library work)

| Contract | ~Size (B) | Over by |
|----------|-----------|---------|
| `Zeto_AnonEncNullifierKyc` | 29,882 | ~5,306 |
| `Zeto_AnonEncNullifierNonRepudiation` | 28,763 | ~4,187 |
| `Zeto_AnonEncNullifier` | 27,627 | ~3,051 |
| `Zeto_AnonNullifierQurrency` | 26,876 | ~2,300 |
| `Zeto_AnonNullifierKyc` | 26,602 | ~2,026 |
| `Zeto_AnonNullifierBurnable` | 24,695 | ~119 |
| `Groth16Verifier_AnonEncNullifierNonRepudiationBatch` | 24,844 | ~268 |

Test suites that deploy exempt tokens are skipped via `describeZetoToken` in `test/lib/eip170.ts` until implementations fit.

---

## Proposed library splits (not yet implemented)

Goal: move large, mostly pure logic out of token **implementations** into `library` contracts (linked at deploy time). Token bytecode retains `DELEGATECALL`/`CALL` stubs; heavy algorithms live in libraries that can be shared across variants.

### 1. `ZetoEncPublicInputsLib` (highest impact on enc\* tokens)

**Problem:** `Zeto_AnonEncNullifier` and descendants duplicate substantial public-inputs assembly for encrypted transfers (ECDH nonces, ciphertext packing, locked vs unlocked paths). `Zeto_AnonEncNullifier` alone is ~3 KiB over limit while `Zeto_AnonNullifier` is still under.

**Move from:** `zeto_anon_enc_nullifier.sol`, `zeto_anon_enc.sol`, enc-specific overrides in lockable paths.

**Candidates:**

- `_calcSize_EncNullifier`, `_fillPublicInputs_*` style helpers
- ECDH / encryption nonce serialization shared with `Zeto_AnonEnc`

**Consumers:** `Zeto_AnonEncNullifier`, `Zeto_AnonEncNullifierKyc`, `Zeto_AnonEncNullifierNonRepudiation`.

**Estimated savings:** ~2–4 KiB per enc implementation (largest lever for the enc stack).

### 2. `ZetoLockableTransitionLib`

**Problem:** `ZetoLockable` (~600 lines) is inlined through `ZetoFungible` / nullifier hierarchies. Lock lifecycle (create/update/delegate/spend/cancel) is circuit-agnostic but bytecode-heavy.

**Move from:** `lib/zeto_lockable.sol` — keep thin storage + external entrypoints on the token; move `_doLockTransition` support, hash-domain helpers, and padding orchestration that does not need `storage` to the library.

**Consumers:** All nullifier tokens with lock support, enc variants with locked spends.

**Estimated savings:** ~1–2 KiB where lockable is included (already shared as abstract contract; library linking deduplicates across deployments).

### 3. `ZetoRegistryLib` (KYC variants)

**Problem:** `Zeto_AnonNullifierKyc` / `Zeto_AnonEncNullifierKyc` inherit `Registry` (identities tree membership checks) on top of already-large bases.

**Move from:** `lib/registry.sol` — membership proofs, root handling, and `register` validation that can be `internal` library calls.

**Consumers:** `Zeto_AnonNullifierKyc`, `Zeto_AnonEncNullifierKyc`.

**Estimated savings:** ~1–2 KiB per KYC token.

### 4. `ZetoQurrencyPublicInputsLib`

**Problem:** `Zeto_AnonNullifierQurrency` adds Kyber-oriented auditability encoding (`_calcSize_Qurrency`, `_fillPublicInputs_Qurrency`, buffer management in storage).

**Move from:** `zeto_anon_nullifier_qurrency.sol`.

**Consumers:** `Zeto_AnonNullifierQurrency` only.

**Estimated savings:** ~2–3 KiB (targets the qurrency-specific gap).

### 5. `ZetoBurnPublicInputsLib`

**Problem:** `Zeto_AnonNullifierBurnable` is only ~119 B over — smallest fix.

**Move from:** `lib/zeto_fungible_burn_nullifier.sol` burn/nullifier public-inputs construction.

**Consumers:** `Zeto_AnonNullifierBurnable`, potentially `Zeto_AnonBurnable`.

**Estimated savings:** ~0.5–1 KiB (may be enough without other splits).

### 6. `ZetoNonRepudiationLib` + verifier split

**Problem:** `Zeto_AnonEncNullifierNonRepudiation` and `Groth16Verifier_AnonEncNullifierNonRepudiationBatch` both exceed the limit.

**Token side:** Move non-repudiation-specific public-inputs and escrow hash binding from the token into `ZetoNonRepudiationLib`.

**Verifier side:** The batch Groth16 verifier is a generated monolith (~24.8 KiB). Options (pick one in a follow-up):

- Regenerate/split circuit verification across two linked library contracts (custom codegen post-process), or
- Deploy two half-verifiers + router contract (higher integration cost).

**Estimated savings:** ~1–3 KiB token; verifier may need a dedicated circuit/tooling change.

### Suggested implementation order

1. **`ZetoBurnPublicInputsLib`** — unblocks `Zeto_AnonNullifierBurnable` with minimal surface.
2. **`ZetoEncPublicInputsLib`** — unblocks the enc\* family (largest user-facing gap).
3. **`ZetoRegistryLib`** + **`ZetoQurrencyPublicInputsLib`** — KYC and qurrency variants.
4. **`ZetoLockableTransitionLib`** — broad reuse, moderate effort.
5. **Non-repudiation** token lib + verifier architecture decision.

After each step: remove the contract from `EIP170_EXEMPT_CONTRACTS` in `config/eip170.ts`, re-enable the matching test suite, and confirm `npm run size` reports compliance.

### Deployment notes

- Link libraries in Ignition (`scripts/tokens/*.ts` already pass `libraries` for `SmtLib` / Poseidon). Extend the same pattern for new libs.
- UUPS **implementation** must stay under 24,576 B; ERC-1967 proxies are tiny.
- Factory clones (`ZetoTokenFactory`) still require a one-time under-limit implementation deploy.
