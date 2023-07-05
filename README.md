# zkdvrf

A  distributed verifiable random function (DVRF) is a $t$-out-of-$n$ threshold scheme that enables 
a group of n participants to jointly compute a random output. The output is unique, publicly verifiable, 
unpredictable, and unbiased. 

This repository implements a DVRF using threshold cryptography, zksnarks, and bls-signatures. 
The main components of this DVRF are:
- A snark-based non-interactive distributed key generation (NI-DKG)
- Randomness generation based on threshold bls-signatures
