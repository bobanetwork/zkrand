/**
 * @type import('hardhat/config').HardhatUserConfig
 */
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
