/**
 * EIP-170 (Spurious Dragon) maximum deployed runtime bytecode size.
 * @see https://eips.ethereum.org/EIPS/eip-170
 */
export const EIP170_BYTE_LIMIT = 24_576;

/**
 * Production contracts that currently exceed EIP170_BYTE_LIMIT with the
 * compiler settings in hardhat.config.ts. Exempt from `hardhat-contract-sizer`
 * strict checks until library splits land (see docs/EIP170-contract-size.md).
 *
 * Remove names from this list as implementations are brought under the limit.
 */
export const EIP170_EXEMPT_CONTRACTS: readonly string[] = [
  "Zeto_AnonEncNullifier",
  "Zeto_AnonEncNullifierKyc",
  "Zeto_AnonEncNullifierNonRepudiation",
  "Zeto_AnonNullifierBurnable",
  "Zeto_AnonNullifierKyc",
  "Zeto_AnonNullifierQurrency",
  "Groth16Verifier_AnonEncNullifierNonRepudiationBatch",
] as const;

export const EIP170_EXEMPT_CONTRACTS_SET = new Set<string>(
  EIP170_EXEMPT_CONTRACTS,
);

export const EIP170_EXEMPT_DOC = "docs/EIP170-contract-size.md";

export function eip170SkipSuffix(contractName: string): string {
  if (!EIP170_EXEMPT_CONTRACTS_SET.has(contractName)) {
    return "";
  }
  return ` (skipped: ${contractName} exceeds EIP-170 ${EIP170_BYTE_LIMIT} bytes — see ${EIP170_EXEMPT_DOC})`;
}
