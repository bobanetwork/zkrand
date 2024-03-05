/**
 * @type import('hardhat/config').HardhatUserConfig
 */
import { HardhatUserConfig } from 'hardhat/types'
import '@nomiclabs/hardhat-ethers'
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
  solidity: {
    compilers: [{
      version: '0.8.24',
      settings: {
        optimizer: { enabled: true, runs: 200 }
      }
    }],
    overrides: {
      'contracts/PseudoRand.sol': altCompilerSettings,
    }
  }
};
