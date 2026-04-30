import { ethers, ignition } from "hardhat";
import { Logger, ILogObj } from "tslog";
const logLevel = process.env.LOG_LEVEL || "3";
export const logger: Logger<ILogObj> = new Logger({
  name: "deploy_cloneable",
  minLevel: parseInt(logLevel),
});

import erc20Module from "../ignition/modules/erc20";
import { getLinkedContractFactory, deploy } from "./lib/common";

export async function deployFungible(tokenName: string) {
  const { erc20 } = await ignition.deploy(erc20Module);
  const verifiersDeployer = require(`./tokens/${tokenName}`);
  const { deployer, args, libraries } =
    await verifiersDeployer.deployDependencies();

  let zetoFactory;
  if (libraries) {
    zetoFactory = await getLinkedContractFactory(tokenName, libraries);
  } else {
    zetoFactory = await ethers.getContractFactory(tokenName);
  }

  const zetoImpl: any = await zetoFactory.deploy();
  await zetoImpl.waitForDeployment();
  // Do not call {initialize} or {setERC20} on the implementation. Leaf Zeto
  // contracts lock the impl with {_disableInitializers} in the constructor,
  // so {initialize} here would always revert with {InvalidInitialization}.
  // Factory tests ({ZetoTokenFactory}) deploy ERC1967 proxies whose constructor
  // delegates {initialize} into fresh proxy storage; {deployZeto} then binds
  // ERC20 on each proxy via {setERC20}.

  logger.debug(`ERC20 deployed:     ${erc20.target}`);
  logger.debug(`ZetoToken impl deployed: ${zetoImpl.target}`);

  return { deployer, zetoImpl, erc20, args };
}

export async function deployNonFungible(tokenName: string) {
  const [deployer] = await ethers.getSigners();
  const verifiersDeployer = require(`./tokens/${tokenName}`);
  const { args, libraries } = await verifiersDeployer.deployDependencies();

  let zetoFactory;
  if (libraries) {
    zetoFactory = await getLinkedContractFactory(tokenName, libraries);
  } else {
    zetoFactory = await ethers.getContractFactory(tokenName);
  }
  const zetoImpl: any = await zetoFactory.deploy();
  await zetoImpl.waitForDeployment();
  // Same rationale as {deployFungible}: impl stays uninitialized; proxies
  // created by the factory run {initialize} via ERC1967Proxy constructor data.

  logger.debug(`ZetoToken impl deployed: ${zetoImpl.target}`);

  return { deployer, zetoImpl, args };
}

deploy(deployFungible, deployNonFungible)
  .then(() => {
    if (process.env.TEST_DEPLOY_SCRIPTS == "true") {
      return;
    }
    process.exit(0);
  })
  .catch((error) => {
    logger.error(error);
    process.exit(1);
  });
