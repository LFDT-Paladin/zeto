// set this to turn off paramters checking in the deployment scripts
process.env.TEST_DEPLOY_SCRIPTS = "true";

import {
  deployFungible as deployFungibleUpgradeable,
  deployNonFungible as deployNonFungibleUpgradeable,
} from "../../scripts/deploy_upgradeable";
import {
  deployFungible as deployFungibleCloneable,
  deployNonFungible as deployNonFungibleCloneable,
} from "../../scripts/deploy_cloneable";
import fungibilities from "../../scripts/tokens.json";
import { logger } from "./utils";
import { ethers } from "hardhat";

export async function deployZeto(tokenName: string) {
  let zeto, erc20, deployer;

  // for testing with public chains, skip deployment if
  // the contract address is provided
  if (process.env.ZETO_ADDRESS && process.env.ERC20_ADDRESS) {
    zeto = await ethers.getContractAt(tokenName, process.env.ZETO_ADDRESS);
    erc20 = await ethers.getContractAt(
      "SampleERC20",
      process.env.ERC20_ADDRESS,
    );
    deployer = (await ethers.getSigners())[0];
    return { deployer, zeto, erc20 };
  }

  let isFungible = false;
  const fungibility = (fungibilities as any)[tokenName];
  if (fungibility === "fungible") {
    isFungible = true;
  }

  if (process.env.USE_FACTORY !== "true") {
    logger.debug("Deploying as upgradeable contracts");
    // setup via the deployment scripts
    const deployFunc = isFungible
      ? deployFungibleUpgradeable
      : deployNonFungibleUpgradeable;
    const result = await deployFunc(tokenName);
    ({ deployer, zeto, erc20 } = result as any);
  } else {
    logger.debug('Deploying as cloneable contracts using "ZetoTokenFactory"');
    let args, zetoImpl;
    const deployFunc = isFungible
      ? deployFungibleCloneable
      : deployNonFungibleCloneable;
    const result = await deployFunc(tokenName);
    ({ deployer, zetoImpl, erc20, args } = result as any);
    let [name, symbol, deployerAddr, verifiers] = args;

    // we want to test the effectiveness of the factory contract
    // to create clones of the Zeto implementation contract
    const Factory = await ethers.getContractFactory("ZetoTokenFactory");
    const factory = await Factory.deploy();
    await factory.waitForDeployment();

    const implInfo = {
      implementation: zetoImpl.target,
      verifiers,
    };
    const tx1 = await factory
      .connect(deployer)
      .registerImplementation(tokenName, implInfo as any);
    await tx1.wait();
    let tx2;
    if (isFungible) {
      tx2 = await factory
        .connect(deployer)
        .deployZetoFungibleToken(name, symbol, tokenName, deployerAddr);
    } else {
      tx2 = await factory
        .connect(deployer)
        .deployZetoNonFungibleToken(name, symbol, tokenName, deployerAddr);
    }
    const result1 = await tx2.wait();

    let zetoAddress;
    for (const log of result1!.logs) {
      const event = factory.interface.parseLog(log as any);
      if (event?.name === "ZetoTokenDeployed") {
        zetoAddress = event!.args!.zetoToken;
      }
    }
    zeto = await ethers.getContractAt(tokenName, zetoAddress);

    // set the ERC20 token for the fungible Zeto token
    if (isFungible) {
      const tx3 = await zeto.connect(deployer).setERC20(erc20.target);
      await tx3.wait();
    }
  }

  return { deployer, zeto, erc20 };
}
