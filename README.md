# zkDVRF

A  distributed verifiable random function (DVRF) is a t-out-of-n threshold scheme that enables 
a group of n participants to jointly compute a random output. The output should be unique, publicly verifiable, 
unpredictable, and unbiased. 

This repository implements a DVRF using threshold cryptography, zksnarks, and bls-signatures. 
The main components of this DVRF are:
* A snark-based non-interactive distributed key generation (NI-DKG):  We use Halo2 with KZG commitment on the bn256 curve to generate the SNARK proof. Our DKG circuit proves the following computation is performed correctly:
    - Secret shares are computed consistently from coefficents
    - Public shares are generated from secret shares: public shares are computed on Bn256 curve. In the circuit, we use non-native encoding of bn256 from halo2wrong to create gates. 
    - Encryption of secret shares: encryptions are performed on Grumpkin curve. We developed ecc chip for generating gates in the circuit where scalar multiplication currently uses a double-and-add method with optimisations customised for halo2wrong's maingate.   
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
| (3,5)  |  19    |   39.641        |	5.588           |	3840	           |       10          | 
| (7,12) |  20	  |   80.711        |	5.899	        |       3840	           |       19          | 
| (14, 26) |  21  |   161.094	    |   6.538	        |       3840	           |       37          |
| (27, 53) |  22  |   323.833       |	7.859           |	3840	           |       73          | 
| (54, 107) | 23  |   646.967       |	10.334	        |       3840               |	   146         |


DVRF benchmark evaluates the performance of the DVRF functions excluding NI-DKG. 

| (t,n)  |  partial_eval (ms) |	verify_partial_eval (ms) |	combine (ms) |	verify_pseudo_random (ms) |
|:------:|:------------------:|:------------------------:|:-----------------:|:--------------------------:|
|(3,5)   |	0.894         |	   1.065                 |	0.650	     |         1.655              |   
| (7,12) |		      |                          |	1.495	     |                            |
|(14, 26)|		      |                          |      2.976	     |                            | 
|(27, 53)|		      |                          |      5.743        |                            |   	
|(54, 107)|		      |                          |      11.562       |                            | 	

The performance of a single partial evaluation, its verification, and the verification of the final pseudorandom 
value are independent of the values of (t,n). Therefore, we only put the timing results for the (3,5) row.


### TODO
- [ ] Fixed point scalar multiplication optimisations for non-native ecc chip 
- [ ] Windowed scalar multiplication for grumpkin chip
- [ ] Integration with recursive snarks for NI-DKG
