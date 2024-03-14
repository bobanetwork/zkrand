# zkDVRF

A  distributed verifiable random function (DVRF) is a t-out-of-n threshold scheme that enables 
a group of n participants to jointly compute a random output. The output should be unique, publicly verifiable, 
unpredictable, and unbiased. 

This repository implements a DVRF using threshold cryptography, zksnarks, and bls-signatures. 
The main components of this DVRF are:
* A snark-based non-interactive distributed key generation (NI-DKG):  We use Halo2 with KZG commitment on the Bn256 curve to generate the SNARK proof. Our DKG circuit proves the following computation is performed correctly:
    - Secret shares are computed consistently from coefficents
    - Public shares are generated from secret shares and global public key is computed correctly. Public shares are computed on Bn256 G1 and the global public key is computed on Bn256 G2. 
  In the circuit, we use non-native encoding of Bn256 from halo2wrong to create gates. As our protocol only requires a fixed generator $g_1$ for creating public shares, we have developed a windowed scalar multiplication chip for fixed point generator which reduced 70% of gates. 
  We also developed G2 chip for computing scalar multiplication on G2. 
    - Encryption of secret shares: encryptions are performed on Grumpkin curve instead of Bn256. We developed ecc chip for generating gates in the circuit where scalar multiplication currently uses a double-and-add method with optimisations customised for halo2wrong's maingate. Since the base field of Grumpkin is the same as the scalar field of Bn256, the size of the scalar multiplication circuit for Grumpkin is about 25 times smaller than the non-native encoding of Bn256.   
* Randomness generation based on threshold bls-signatures: After completing the NI-DKG process, participants can use their DKG secret keys to create pseudo-random values. 

### Benchmarks
Benchmarks can be run using:

```
$ cargo bench
```

NI-DKG benchmark can be switched on by uncommenting it in Cargo.toml.
Below are the evaluation results running on AWS instance r6i.8xlarge, which has 32 CPUs and 256GB of memory.

NI-DKG without G2 chip:

| degree |  (t, n)   | snark_prove (s) | snark_verify (ms) | snark proof size (Bytes) | memory usage (GB) |
|:--------------:|:---------:|:---------------:|:-----------------:|:------------------------:|:-----------------:|
|  18   |   (5,9)   |     19.908      |      	5.1817      |          	3488	          |        4.6        | 
|  19	 |  (11,21)  |     37.616      |     	5,5494	      |          3488	           |        8.8        | 
|  20   | (22, 43)  |     74.689      |      6.2203       |          3488	           |       16.6        |
|  21   | (45, 88)  |     147.650     |      	7.5934      |          	3488	          |       32.6        | 
|  22   | (89, 176) |     295.792     |     	10.270	      |           3488           |     	   64.4      |


NI-DKG with G2 chip:

| degree |  (t, n)   | snark_prove (s) | snark_verify (ms) | snark proof size (Bytes) | memory usage (GB) |
|:--------------:|:---------:|:---------------:|:-----------------:|:------------------------:|:-----------------:|
|  18   |   (3,5)   |     20.758      |      	5.0838      |          	3488	          |        4.8        |
|  19	 |  (9,16)   |     38.055      |     	5.4085	      |          3488	           |        8.8        |
|  20   | (20, 38)  |     74.738      |      6.0364       |          3488	           |       16.5        |
|  21   | (42, 83)  |     148.438     |      	7.3965      |          	3488	          |       32.5        |
|  22   | (86, 171) |     294.286     |     	10.139	      |           3488           |     	   64.4      |


The proof size remains constant and the verification time can be further reduced by hashing the public inputs which is not yet implemented. 

DVRF benchmark evaluates the performance of the DVRF functions excluding NI-DKG. 

|   (t,n)   | partial_eval (ms) | 	verify_partial_eval (ms) | 	combine (ms) | 	verify_pseudo_random (ms) |
|:---------:|:-----------------:|:-------------------------:|:-------------:|:--------------------------:|
|   (3,5)   |      	0.856       |        	   1.0262         |    	0.650	    |           1.6194           |   
|  (9,16)   |        		         |                           |   	1.9135	    |                            |
| (20, 38)  |        		         |                           |    4.2424	    |                            | 
| (42, 83)  |        		         |                           |    8.9423     |                            |   	
| (86, 171) |        		         |                           |    18.517     |                            | 	

The performance of a single partial evaluation, its verification, and the verification of the final pseudorandom 
value are independent of the values of (t,n). Therefore, we only put the timing results for the first row.