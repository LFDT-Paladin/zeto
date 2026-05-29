import { artifacts } from "hardhat";
import {
  EIP170_BYTE_LIMIT,
  EIP170_EXEMPT_TOKEN_SET,
} from "../../config/eip170";

/**
 * Assert a token implementation fits EIP-170 before deploy when it is not exempt.
 * Hardhat Network runs with allowUnlimitedContractSize enabled (see hardhat.config.ts);
 * exempt tokens may exceed the limit.
 */
export async function assertEip170Compliant(tokenName: string): Promise<void> {
  if (EIP170_EXEMPT_TOKEN_SET.has(tokenName)) {
    return;
  }
  const artifact = await artifacts.readArtifact(tokenName);
  const deployedBytes = (artifact.deployedBytecode.length - 2) / 2;
  if (deployedBytes > EIP170_BYTE_LIMIT) {
    throw new Error(
      `${tokenName} deployed bytecode is ${deployedBytes} bytes, exceeding EIP-170 limit ${EIP170_BYTE_LIMIT}`,
    );
  }
}
