import {
  EIP170_EXEMPT_CONTRACTS_SET,
  eip170SkipSuffix,
} from "../../config/eip170";

export { EIP170_EXEMPT_CONTRACTS_SET, eip170SkipSuffix };

/**
 * Use instead of `describe` for suites that deploy a token implementation
 * that may be on the EIP-170 exemption list (Hardhat enforces the limit when
 * `allowUnlimitedContractSize` is false).
 */
export function describeZetoToken(
  tokenName: string,
  suiteTitle: string,
  fn: (this: Mocha.Suite) => void,
): void {
  const runner = EIP170_EXEMPT_CONTRACTS_SET.has(tokenName)
    ? describe.skip
    : describe;
  runner(suiteTitle + eip170SkipSuffix(tokenName), fn);
}
