# Zeto Solidity contracts

Privacy-preserving token implementations for fungible and non-fungible assets, built with the Zeto ZK toolkit (Groth16 circuits, UTXO model, optional nullifiers and encryption).

## Prerequisites

- Node.js (see repo CI for supported versions).
- From this directory (`solidity/`), install dependencies:

  ```console
  npm install
  ```

  Hardhat and related tooling are pulled in via `@nomicfoundation/hardhat-toolbox`; you do not need to run `hardhat init` in this repository.

### Circuits and proving keys

Hardhat tests load circuit WASM via **`zeto-js`** (`file:../zkp/js`). Before running tests:

1. Build **zkp/js** and produce **proving keys** and verification artifacts as described in [`../zkp/js/README.md`](../zkp/js/README.md) (build section).
2. Ensure **`zeto-js` unit tests pass** in `zkp/js` before relying on Solidity tests here.
3. Set environment variables so tests can find WASM and keys (same layout as CI):

   - **`CIRCUITS_ROOT`**: directory containing compiled circuit artifacts (e.g. `anon_js/`, `anon_nullifier_transfer_js/`, …).
   - **`PROVING_KEYS_ROOT`**: directory containing the proving key files referenced by the test harness.

Example:

```console
export CIRCUITS_ROOT=/path/to/zeto-artifacts
export PROVING_KEYS_ROOT=/path/to/zeto-artifacts
npm test
```

### `@iden3/contracts` (nullifier / SMT)

Tokens that use nullifiers depend on iden3’s Sparse Merkle Tree Solidity library. This workspace expects it at **`../../contracts`** relative to `solidity/` (see `package.json`: `"@iden3/contracts": "file:../../contracts"`).

Clone [kaleido-io/contracts](https://github.com/kaleido-io/contracts) (branch **`keccak256`**) next to the **zeto** repo root so the layout is:

```text
contracts/          # iden3 SMT package (branch keccak256)
  package.json
  ...
zeto/
  solidity/
  zkp/
  ...
```

Run **`npm install`** in the **`contracts`** checkout so the file dependency resolves.

## Deploying token contracts

Scripts deploy the token named by **`ZETO_NAME`** (see `scripts/tokens.json` / Ignition modules for valid names).

### Upgradeable (UUPS proxy)

Deploys the implementation plus an ERC1967 proxy and runs `initialize`. Suitable when you want upgradeability via OpenZeppelin’s UUPS pattern.

```console
export ZETO_NAME=Zeto_AnonEncNullifier
npx hardhat run scripts/deploy_upgradeable.ts
```

Background: [Transparent vs UUPS proxies](https://docs.openzeppelin.com/contracts/5.x/api/proxy#transparent-vs-uups), [Upgrades plugin](https://docs.openzeppelin.com/upgrades-plugins/proxies).

### Cloneable / factory workflow

```console
export ZETO_NAME=Zeto_AnonEncNullifier
npx hardhat run scripts/deploy_cloneable.ts
```

This deploys the **implementation only**. Leaf tokens lock the impl with `_disableInitializers()`; **`initialize` runs on proxies** created by **`ZetoTokenFactory`**. Tests use **`USE_FACTORY=true`** in `test/lib/deploy.ts` to register the impl and deploy initialized clones. Running the script **by itself** does not yield a ready-to-use initialized token unless you finish that factory flow.

For a single initialized deployment without the factory path, use **`deploy_upgradeable.ts`**.

Cheap repeat deployments: OpenZeppelin [minimal proxies / Clones](https://docs.openzeppelin.com/contracts/5.x/api/utils#Clones).

## Running tests

```console
npm install
npm test
```

`pretest` runs Prettier on `contracts`, `scripts`, `ignition`, and `test`; fix formatting or run `npm run prettier:fix` if the check fails.

Optional:

- **`USE_FACTORY=true`**: exercise the factory deployment path (cloneable impl + `ZetoTokenFactory`) in addition to the default upgradeable path when relevant tests support it.

Successful runs exercise mint/transfer/withdraw flows, nullifier trees, registry helpers, DvP samples, and gas-heavy suites depending on which circuits and keys are present.

## Further reading

- Token variants and feature matrix: [`doc-site/docs/implementations/`](../doc-site/docs/implementations/) (repository root).
- Circuit sources: [`../zkp/circuits/`](../zkp/circuits/).
