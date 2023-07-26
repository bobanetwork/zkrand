# zkDVRF

A  distributed verifiable random function (DVRF) is a t-out-of-n threshold scheme that enables 
a group of n participants to jointly compute a random output. The output should be unique, publicly verifiable, 
unpredictable, and unbiased. 

This repository implements a DVRF using threshold cryptography, zksnarks, and bls-signatures. 
The main components of this DVRF are:
* A snark-based non-interactive distributed key generation (NI-DKG):  We use Halo2 with KZG commitment on the Bn256 curve to generate the SNARK proof. Our DKG circuit proves the following computation is performed correctly:
    - Secret shares are computed consistently from coefficents
    - Public shares are generated from secret shares: public shares are computed on Bn256 curve. In the circuit, we use non-native encoding of Bn256 from halo2wrong to create gates. As our protocol only requires a fixed generator $g_1$ for creating public shares, we have developed a windowed scalar multiplication chip for fixed point generator which reduced 70% of gates.
    - Encryption of secret shares: encryptions are performed on Grumpkin curve instead of Bn256. We developed ecc chip for generating gates in the circuit where scalar multiplication currently uses a double-and-add method with optimisations customised for halo2wrong's maingate. Since the base field of Grumpkin is the same as the scalar field of Bn256, the size of the scalar multiplication circuit for Grumpkin is about 25 times smaller than the non-native encoding of Bn256.   
* Randomness generation based on threshold bls-signatures: After completing the NI-DKG process, participants can use their DKG secret keys to create pseudo-random values. 

### Benchmarks
Benchmarks can be run using:

```
$ cargo bench
```

NI-DKG benchmark can be switched on by uncommenting it in Cargo.toml.
Below are the evaluation results running on AWS instance r6i.8xlarge, which has 32 CPUs and 256GB of memory. 

| (t, n) | degree | snark_prove (s) | snark_verify (ms) | snark proof size (Bytes) | memory usage (GB) |
|:------:|:------:|:---------------:|:-----------------:|:------------------------:|:-----------------:|
| (5,9)  |  18    |   20.889       |	5.761           |	3840	           |       5          | 
| (11,21) |  19	  |   40.043        |	6.375	        |       3840	           |       10          | 
| (22, 43) |  20  |   80.996        |   7.362	        |       3840	           |       19          |
| (45, 88) |  21  |   161.630       |	9.544           |	3840	           |       37          | 
| (89, 177) | 22  |   322.693       |	13.837	        |       3840               |	   73         |


DVRF benchmark evaluates the performance of the DVRF functions excluding NI-DKG. 

| (t,n)  |  partial_eval (ms) |	verify_partial_eval (ms) |	combine (ms) |	verify_pseudo_random (ms) |
|:------:|:------------------:|:------------------------:|:-----------------:|:--------------------------:|
| (5,9)    |	0.891         |	   1.064                 |	1.071	     |         1.655              |   
| (11,21) |		      |                          |	2.336	     |                            |
|(22, 43)|		      |                          |      4.667	     |                            | 
|(45, 88)|		      |                          |      9.604        |                            |   	
|(89, 177)|		      |                          |      19.171       |                            | 	

The performance of a single partial evaluation, its verification, and the verification of the final pseudorandom 
value are independent of the values of (t,n). Therefore, we only put the timing results for the first row.


### TODO
- [x] Fixed point scalar multiplication optimisations for non-native ecc chip 
- [ ] Windowed scalar multiplication for grumpkin chip
- [ ] Integration with recursive snarks for NI-DKG
