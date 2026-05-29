/**
 * EIP-170 (Spurious Dragon) maximum deployed runtime bytecode size.
 * @see https://eips.ethereum.org/EIPS/eip-170
 */
export const EIP170_BYTE_LIMIT = 24_576;

/**
 * Contracts that currently exceed EIP170_BYTE_LIMIT with the compiler settings
 * in hardhat.config.ts. Exempt from `hardhat-contract-sizer` strict checks
 * until further library splits land.
 *
 * Remove names from this list as implementations are brought under the limit.
 */
export const EIP170_EXEMPT_CONTRACTS: readonly string[] = [
  "Zeto_AnonEncNullifier",
  "Zeto_AnonEncNullifierKyc",
  "Zeto_AnonEncNullifierNonRepudiation",
  "Zeto_AnonNullifierBurnable",
  "Zeto_AnonNullifierQurrency",
  "Groth16Verifier_AnonEncNullifierNonRepudiationBatch",
] as const;

export const EIP170_EXEMPT_CONTRACTS_SET = new Set<string>(
  EIP170_EXEMPT_CONTRACTS,
);

/** Token implementations in the exemption list (excludes standalone verifiers). */
export const EIP170_EXEMPT_TOKEN_SET = new Set<string>(
  EIP170_EXEMPT_CONTRACTS.filter((name) => name.startsWith("Zeto_")),
);
