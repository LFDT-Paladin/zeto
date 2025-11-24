import { ethers, ignition, upgrades } from "hardhat";
import { Logger, ILogObj } from "tslog";
const logLevel = process.env.LOG_LEVEL || "3";
export const logger: Logger<ILogObj> = new Logger({ name: "deploy_upgradeable", minLevel: parseInt(logLevel) });

import erc20Module from "../ignition/modules/erc20";
import { getLinkedContractFactory, deploy } from "./lib/common";

export async function deployFungible(tokenName: string, erc20Address?: string) {
  let erc20: any;
  if (!erc20Address) {
    ({ erc20 } = await ignition.deploy(erc20Module));
    logger.debug(`ERC20 deployed:     ${erc20.target}`);
  } else {
    erc20 = await ethers.getContractAt("SampleERC20", erc20Address);
    if (!erc20) {
      throw new Error(`ERC20 contract not found at address: ${erc20Address}`);
    }
    logger.debug(`Using existing ERC20 contract at: ${erc20.target}`);
  }
  const verifiersDeployer = require(`./tokens/${tokenName}`);
  const { deployer, args, libraries } =
    await verifiersDeployer.deployDependencies();

  let zetoFactory;
  const opts = {
    kind: "uups",
    initializer: "initialize",
    unsafeAllow: ["delegatecall"],
  };
  if (libraries) {
    zetoFactory = await getLinkedContractFactory(tokenName, libraries);
    opts.unsafeAllow.push("external-library-linking");
  } else {
    zetoFactory = await ethers.getContractFactory(tokenName);
  }

  const proxy = await upgrades.deployProxy(zetoFactory, args, opts as any);
  await proxy.waitForDeployment();
  const zetoAddress = await proxy.getAddress();
  const zeto: any = await ethers.getContractAt(tokenName, zetoAddress);

  const tx3 = await zeto.connect(deployer).setERC20(erc20.target);
  await tx3.wait();

  logger.debug(`ZetoToken deployed: ${zeto.target}`);

  return { deployer, zeto, erc20 };
}

export async function deployNonFungible(tokenName: string) {
  const verifiersDeployer = require(`./tokens/${tokenName}`);
  const { deployer, args, libraries } =
    await verifiersDeployer.deployDependencies();

  let zetoFactory;
  const opts = {
    kind: "uups",
    initializer: "initialize",
    unsafeAllow: ["delegatecall"],
  };
  if (libraries) {
    zetoFactory = await getLinkedContractFactory(tokenName, libraries);
    opts.unsafeAllow.push("external-library-linking");
  } else {
    zetoFactory = await ethers.getContractFactory(tokenName);
  }

  const proxy = await upgrades.deployProxy(zetoFactory, args, opts as any);
  await proxy.waitForDeployment();
  const zetoAddress = await proxy.getAddress();
  const zeto: any = await ethers.getContractAt(tokenName, zetoAddress);

  logger.debug(`ZetoToken deployed: ${zeto.target}`);

  return { deployer, zeto };
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
