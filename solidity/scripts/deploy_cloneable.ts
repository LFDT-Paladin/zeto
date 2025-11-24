import { ethers, ignition } from "hardhat";
import { Logger, ILogObj } from "tslog";
const logLevel = process.env.LOG_LEVEL || "3";
export const logger: Logger<ILogObj> = new Logger({ name: "deploy_cloneable", minLevel: parseInt(logLevel) });

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
  // console.log(args);
  await zetoImpl.connect(deployer).initialize(...args);

  const tx3 = await zetoImpl.connect(deployer).setERC20(erc20.target);
  await tx3.wait();

  logger.debug(`ERC20 deployed:     ${erc20.target}`);
  logger.debug(`ZetoToken deployed: ${zetoImpl.target}`);

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
  await zetoImpl.connect(deployer).initialize(...args);

  logger.debug(`ZetoToken deployed: ${zetoImpl.target}`);

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
