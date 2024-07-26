#!/bin/bash
set -uex

degree=22

params_dir="kzg_params"
mkdir -p "$params_dir"

degree_output_file="$params_dir"/params"${degree}"
rm -f "$degree_output_file"

# https://docs.axiom.xyz/docs/transparency-and-security/kzg-trusted-setup
axel -ac https://axiom-crypto.s3.amazonaws.com/challenge_0085/kzg_bn254_"${degree}".srs -o "$degree_output_file"