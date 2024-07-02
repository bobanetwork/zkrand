# zkRand

zkRand is a t-out-of-n threshold scheme that runs among a group of n distributed members. The protocol consists of two components:
a snark-based non-interactive distributed key generation (NI-DKG) and randomness generation based on threshold bls-signatures.

### To build:

```
$ cargo build --release
```

For help information
```
$ ./target/release/client -h
```

### Protocol steps
1. Download KZG parameters using: 
    ```
    sh download_params.sh
    ```
    This downloads KZG parameters with degree = 22 from Ethereum Powers of Tau.
    The parameters are saved in "./kzg_params/params22". This is the KZG ceremony. 

2. Config. This step initialises the protocol configuration. 
The default config is set to be (threshold, number_of_memnbers, degree) = (3, 5, 18). 
This can be changed by:
    ```
    $ RUST_LOG=info ./target/release/client config <THRESHOLD> <NUMBER_OF_MEMBERS> <DEGREE>
    ```
    The configuration is saved at "data/config.toml". The degree determines maximum number of gates allowed in a DNI-KG circuit.
    Higher degree is required for supporting more members in the NI-DKG protocol. 
    The maximun (threshold, number_of_members) that can be supported for a given degree is: 
    
    | degree |   18   | 19 | 20 | 21 | 22 |
    |:------:|:------:| :----: | :----: |  :----: |  :----: |
    | (t, n) | (3, 5) | (9, 16) | (20, 38) | (42, 83) | (86, 171)
    
    The threshold is set as the majority of number_of_members. 

3. Setup. This generates SNARK proving key and verifying key for NI-DKG circuits,
    and the verification contracts for checking SNARK proofs onchain.
    The SNARK parameters are generated using: 
    ```
    $ RUST_LOG=info ./target/release/client setup -s
    ```
    The parameters are computed using Ethereum power-of-tau, 
    therefore, the proving/verifying keys are deterministic given a configuration. 
    The parameters are stored in "./kzg_params" and the generated contracts in "./contracts".
    The option `-s` splits the verifier contract and verifying key contract so that the verifier contract 
    stays the same for different (t,n) values. The verifying key contract needs to be changed when (t,n) changes. 
    The current implementation of contracts set (t,n) to be (3, 5).

4. KeyGen. Before the NI-DKG protocol starts, each member $i$ pre-generates its member public key $mpk_i$ and 
secret key $msk_i$ for encryption and decryption in NI-DKG protocol:
    ```
    $ RUST_LOG=info ./target/release/client keygen
    ```
    The secret key is saved at "./data/members/member.json". The public key is printed in the format:
    ```
      {
        "x":"0x0779273a75396c1c8c874a1b08c8beacf56f0a576142c7251c0be0408554b717",
        "y":"0x2c3c22206625d7c76d319245dcaa5cadfad9d197933966b73def60f67eccbd36"
      }
    ```
    A public key is a point on Grumpkin curve. (x,y) are the point's coordinates 
    which are 256-bit integers and are encoded as hex string.
    Each member submits its member public key to contract "zkdvrf.sol" through 
    function `registerNode`. The hex string may need to be converted to big integers before submitting to the contract.
    In the contract, all the submitted public keys are stored in `pubKeys` and their order is stored in `ppListOrder`. 
    To use these public keys in the following NI-DKG steps, `pubKeys` should be converted to a list that is compatible 
    with the Rust backend:
    
    ```
    [
    {"x1": "...", "y1": "..."}, 
    {"x2": "...", "y2": "..."}, 
    ... 
    {"x5": "...", "y5": "..."},
    ]
    ```
    
    The order follows the order in `ppListOrder` and every member must use the same order.
    Otherwise the SNARK proof verification won't pass. The converted public keys should be saved at "./data/mpks.json"
    for the next steps.


5. NI-DKG. 
   1. Create public parameters. Each member $i$ selects a random polynomial to create its public parameters $pp_i$
   and a SNARK proof $zkp_i$ to ensure the parameters are generated correctly. 
        ```
        $ RUST_LOG=info ./target/release/client dkg prove <INDEX>
        ```
        Index is the member's position in the list of member public keys. The index ranges 1, 2, ..., number_of_members.
        This command reads "./data/mpks.json" to obtain all members public keys. 
        The public keys are used for encrypting the secret shares each member created for other members.
        This command outputs $(pp_i, zkp_i)$ where $pp_i$ is encoded as instance and saved at "./data/dkg/proofs/instance_{INDEX}.json" and
        $zkp_i$ is saved at "./data/dkg/proofs/proof_{INDEX}.dat".
        $(pp_i, zpk_i)$ can be submitted to the contract `zkdvrf.sol` through function `submitPublicParams` for onchain verification.
        $pp_i$ is a list of hex string and needs to be converted to be a list of big integers before sending to the contract.
        $zkp_i$ is bytes and can be directly sent to the contract.

        $(pp_i, zpk_i)$ can also be verified locally using
        ```
        $ RUST_LOG=info ./target/release/client dkg verify <INDEX>
        ```
      This command reads $pp_i$ from "./data/dkg/proofs/instance_{INDEX}.json" 
   and $zkp_i$ from  "./data/dkg/proofs/proof_{INDEX}.dat". 

      The current implementation of contracts expect submission from each member. However, 
      it is in fact not necessary to require each member to generate and submit $pp_i$.
        Instead, a lower bound $m$ with threshold < m <= number_of_members can be set to accept the NI-DKG process.
        For example, m = (2/3) * number_of_members. If at least m members submit valid $(pp_i, zkp_i)$, then the NI-DKG can be considered successfully.
        The members that do not submit will still be able to obtain a secret/verification key pair (in the following steps) as long as their member public keys are included. 
        These members can be allowed or banned from participating in the randomness generation process.
   3. Derive secret shares and global public parameters.  `ppList` in the contract contains 
   all the submitted public parameters from which each member can derive their secret shares and global public parameters. 
    Member $i$ can derive its secret share $sk_i$ and the global public parameters using:

      ```
      $ RUST_LOG=info ./target/release/client dkg derive <INDEX> -f <FILE>
      ```
      This command requires member $i$'s secret key $msk_i$ in "./data/members/FILE.json" and all the
      public parameters in "./data/all_instances.json". The default value of FILE is "member". `ppList` in the contract is of type `uint256[][]`.
   `all_instances.json` is obtained from  `ppList` by converting all the uint256 into hex string. From this command, member $i$ 
   obtains its secret share saved at "./data/dkg/shares/share_{INDEX}.json", a global public key $gpk$ saved at "./data/gpk.json" 
   and all the verification keys saved at "./data/vks.json". Every member can obtain a verification key regardless of whether the 
   member participates in the NI-DKG or not. The verification keys are listed in the same order as the member public keys. 
   The verification key $vk_i$ will be used to verify the partial evaluation generation by member $i$ using its secret share $sk_i$. 

6. Randomness generation: given an unique public string $x$, members jointly generate a pseudorandom value. 
This pseudorandom is deterministic which means only one value can pass the pseudorandom verification `verifyPseudoRand` given $gpk$ and $x$.
   1. Each member $i$ computes a partial evaluation $eval_i$ using:
    ```
    $ RUST_LOG=info ./target/release/client rand eval <INDEX> <INPUT>
    ```
   This command reads member $i$'s secret share $sk_i$ from "./data/dkg/shares/share_{INDEX}.json".
   The output of $eval_i$ is saved at "./data/random/eval_{INDEX}.json".
   The validity of $eval_i$ can be checked against member $i$'s verification key $vk_i$.
   $eval_i$ can be submitted to the contract `zkdvrf.sol` through function `submitPartialEval`.
   An example of $eval_i$ is 
   ```
   {
   "index":1,
   "value":{"x":"0x14144dd3868a1a33384c8f5a4fd5ed0a71723780ad7244f12a2753f013484e6d","y":"0x1e78a56363dc84687bf354f03f000bc1ac1e65d9fca322e275e2d8bcc38d6e9b"},
   "proof":{"z":"0x2effa96d25c37a73ea8a329a9bb366f962ea5ef3fa694520342aa6d0c41a61dd","c":"0x03f4e7780a47099ce6541da29bc1d5e03370a5fdc6075e451cbbef923a7b896a"}
   }
   ```
   All the hex string may need to be converted to big integers before submitting to the contract.
   $eval_i$ can also be verified locally using
   ```
    $ RUST_LOG=info ./target/release/client rand verify <INDEX> <INPUT>
   ```
   This command reads $eval_i$ from "./data/random/eval_{INDEX}.json" and verification keys from "./data/vks.json".

    2. Once there are at least $t$ valid partial evaluations, a combiner can combine these partial evaluations into the final pseudorandom value and generates a proof to show the value is correct.
      The combination process can be performed by any party and it doesn't involve any secret information. To save the onchain verification cost, the combination can be done offchain and
      only the final pseudorandom value and its proof needs to be verified onchain.
    ```
    $ RUST_LOG=info ./target/release/client rand combine <INPUT>
    ```
   This command reads all partial evaluations from "./data/evals.json" 
   and outputs a pseudorandom value saved at "./data/random/pseudo.json". 
   In the contract, all the submitted partial evaluations are stored in `roundToEval` 
which can be used to obtain "evals.json" by converting all the big integers into hex string and changing the map 'roundToEval' to a list of mapped values such as 
   ```
   [
   {"index":1,"value":{"x":"...","y":"..."},"proof":{"z":"...","c":"..."}},
   {"index":2,"value":{"x":"...","y":"..."},"proof":{"z":"...","c":"..."}},
   {"index":3,"value":{"x":"...","y":"..."},"proof":{"z":"...","c":"..."}},
   {"index":4,"value":{"x":"...","y":"..."},"proof":{"z":"...","c":"..."}},
   {"index":5,"value":{"x":"...","y":"..."},"proof":{"z":"...","c":"..."}}
   ]
   ```
    Partial evaluations contain indices, so they do not need to be sorted. The indices are used in the combination algorithm.
    The final pseudorandom value has the format: 
    ```
    {
    "proof":{"x":"0x2028e15050ef4550f0530afad37dfc8928566dbbd31edbe7f244afe3cb0d1c3f","y":"0x0e7b0ecb46b03fb589eedf8136b451f6171b01ce903156768be9e511878df08f"},
    "value":[51,167,113,177,40,238,25,153,158,212,223,21,117,190,95,162,86,65,154,24,164,217,242,200,239,74,162,60,122,208,48,0]
    }
    ```
    It can be submitted to the contract through `submitRandom` for onchain verification and storage. The pseudorandom value is "value" which is the 32-bytes keccak hash of "proof".
    The hex string in "proof" may need to be converted to big integers before submitting. 
   
    The pseudorandom value can also be verified locally:
    ```
    $ RUST_LOG=info ./target/release/client rand verify-final <INPUT>
    ```
    This command reads pseudorandom from "./data/random/pseudo.json".

## Deploy

To deploy the zkRand contracts on-chain-

1. Set up your .env (use .env.example for reference)

```
RPC_URL = <rpc of network to deploy on>
PRIVATE_KEY = <deployer pk>
DEPLOY_NO_HELPERS = <true/false> # optional
HALO2V = <Halo2Verifier address> # optional
HALO2VK = <Halo2VerifyingKey-3-5-18-g2 address> # optional
GPP = <GlobalPublicParam address> # optional
PSRAND = <PseudoRand address> # optional
```

deploying the helpers are optional, and to proceed with using prior-deployed helpers, set `DEPLOY_NO_HELPERS` to true and supply the `HALO2V`, `GPP`, `PSRAND` contract addresses.

If you are unsure, do not set the optional params.

2. Run the deploy script with
```
$ yarn deploy
```

## Running Tests

Run contract tests using-
```
$ yarn test
```

## Running the Demo

The Demo offers a quick, interactive overview of the system's end-to-end flow, including memeber interactions, the different phases and their functionality.

### Step-1: Build

1. Build  by running 

```
$ cargo build --release
```

2. Download KZG parameters using

```
sh download_params.sh
``` 

3. Setup proving key and verifying key. This might take a few minutes. This command also generates SNARK verifier contract.

```
RUST_LOG=info ./target/release/client setup -s
```

4. The demo will require a test blockchain, for a quickstart - download [Ganache](https://archive.trufflesuite.com/ganache/) and start a local network

```
ganache --wallet.seed "my insecure seeds"
```

5. Set up your .env file (use .env.example for reference)

```
RPC_URL=HTTP://127.0.0.1:8545
PRIVATE_KEY=<private-key-from-a-ganache-account>
THRESHOLD=3
NUMBER_OF_MEMBERS=5
DEGREE=18
```

### Step-2: Deploy Contracts

1. To deploy the zkRand contracts, run-

```
yarn deploy
```

2. Populate your demo-config.json file using-

a) your Zkdvrf deployed address
b) five sample addresses, and their private keys from ganache pre-generated accounts

### Step-3: NIDKG

1. Start the demo by running your admin script-

```
yarn admin
```

After adding members on the contract, the admin script needs to be kept running as you move on to the subsequent steps

2. On a separate window, register the members and start the NIDKG process by running-

```
yarn member
```

### Step-4: Generating Random

1. After the NIDKG process is complete, the admin script will automatically initiate a round for random generation. Follow the instructions on the admin window and run the following for the members to submit partial evaluations-

```
yarn random
```

After the members have done submitting partial evaluations - verify that a pseudorandom number is generated on the admin window!
Respond 'yes' on the admin window to start producing the next pseudorandom and 'no' to quit. 

### Re-running
If you have exited the admin script, but have already been through the NIDKG process, you can continue with random number generation through running-

```
yarn admin:restart
```

### Continuing with lottery demo
1. Deploy the lottery contracts

```
yarn lottery:deploy
```

2. Populate your demo-config.json file using-

a) your lottery.sol deployed address
b) private keys for lottery admin and three players from ganache pre-generated accounts

3. Run the lottery admin to start the lottery
```
yarn lottery:admin
```
The lottery will set a target random for picking up a winner. 
The round number for target random is set to be 3 in the script.

4. Run the players to place bets
```
yarn lottery:play
```
Before Zkdvrf starts producing the target random, players can enter the lottery by depositing a certain amount of ethers.

5. Continuing the above Step-4 for generating random until the round number hits 3 which will trigger the lottery admin to pick and pay a winner. 