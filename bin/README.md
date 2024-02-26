To build: 

```
$ cargo build --release
```

For help information
```
$ ./target/release/client -h
```

### Setup
#### config 
The default config (threshold, number_of_members, degree) is set to be (3, 5, 18). This can be modified by 
```
$ RUST_LOG=info ./target/release/client config <THRESHOLD> <NUMBER_OF_MEMBERS> <DEGREE>
```
The configuration is saved at "data/config.toml"

#### setup
```
$ RUST_LOG=info ./target/release/client setup -s
```
This generates KZG parameters, SNARK proving/verifying keys for DKG-circuit, and verification contract for SNARK proofs. 
The parameters are stored in "kzg_params" and the generated contract in "contracts"
The option `-s` splits the verifier contract and verification key contract so that the verifier contract stays the same for different (t,n) values.
The verification key contract is different for different (t,n) values. 

### Mock
Members can be simulated using
```
$ RUST_LOG=info ./target/release/client mock -m
```
It creates all the members secet keys which are stored at "data/members".
All the member public keys are stored at "data/mpks.json".

NI-DKG parameters can be simualted using
```
$ RUST_LOG=info ./target/release/client mock -d
```
It creates parameters for each member. The secret parameters for DKG are stored at "data/dkg/members".
The public parameters for all the members are stored at "data/dkgs_public.json".
The global public parameters are stored in "data/gpp.json".

Partial evaluations and final pseudorandom value on an input string can be simulated using 
```
$ RUST_LOG=info ./target/release/client mock -r <INPUT>
```


### NI-DKG
#### dkg
This starts generating parameters and SNARK proof for NI-DKG for member i.
```
$ RUST_LOG=info ./target/release/client dkg prove <INDEX>
```
The generated SNARK proof and instance is stored at "data/proofs".
It requires all the members' public keys in "data/mpks.json". 
These public keys can be mocked using `mock -m`. 

The SNARK proof and instance can be verified using
```
$ RUST_LOG=info ./target/release/client dkg verify <INDEX>
```
The secret share for member i can be derived using
```
$ RUST_LOG=info ./target/release/client dkg derive <INDEX> <FILE>
```
It also computes the global public parameters for NI-DKG and stores it at "data/gpp.json". 
This command requires member i's secret key in "data/members/<FILE>.json" and the public parameters from all the members which 
is supposed to be available at "data/dkgs_public.json".
Members can be mocked using `mock -m` and the NI-DKG public 
parameters can be mocked using `mock -d`.

The public, i.e., non-members, can also compute the global public parameters using
```
$ RUST_LOG=info ./target/release/client dkg derive
```

### Random generation
#### eval
Partial evaluation on an input string from member i can be computed using
```
$ RUST_LOG=info ./target/release/client rand eval <INDEX> <INPUT>
```
The evaluation result is saved at "data/random/eval_{INDEX}.json". 

#### verify
Partial evaluation can be verified using
```
$ RUST_LOG=info ./target/release/client rand verify <INDEX> <INPUT>
```

#### combine
A set of partial evaluations on an input string can be combined into the final pseudorandom value: 
```
$ RUST_LOG=info ./target/release/client rand combine <INPUT>
```
It requires at least t valid partial evaluations from "./data/random/evals.json".
Partial evaluations can be simulated using `mock -r <INPUT>`.
The final pseudorandom value is saved at "./data/random/pseudo.json".

#### verify-final
The final pseudorandom value on an input string can be verified using:
```
$ RUST_LOG=info ./target/release/client rand verify-final <INPUT>
```