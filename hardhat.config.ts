/**
 * @type import('hardhat/config').HardhatUserConfig
 */
import { HardhatUserConfig } from 'hardhat/types'
import '@nomiclabs/hardhat-ethers'
import 'hardhat-gas-reporter'; // Import gas reporter plugin
import * as dotenv from "dotenv";

dotenv.config();

const altCompilerSettings = {
  version: '0.8.24',
  settings: {
    optimizer: { enabled: true, runs: 200 },
    viaIR: true
  }
}

module.exports = {
  networks: {
    boba_local: {
      url: 'http://localhost:9545',
    },
    boba_sepolia: {
      url: 'https://sepolia.boba.network',
      accounts: process.env.PRIVATE_KEY !== undefined ? [process.env.PRIVATE_KEY] : [],
    } as any,
    boba_mainnet: {
      url: 'https://mainnet.boba.network',
      accounts: process.env.PRIVATE_KEY !== undefined ? [process.env.PRIVATE_KEY] : [],
    },
  },
  solidity: {
    compilers: [{
      version: '0.8.24',
      settings: {
        optimizer: { enabled: true, runs: 200 }
      }
    }],
    overrides: {
      'contracts/PseudoRand.sol': altCompilerSettings,
    },
    gasReporter: {
      enabled: process.env.REPORT_GAS === 'true', // Use environment variable to enable/disable gas reporting
      currency: 'USD',
      gasPrice: 21,
    },
  }
};