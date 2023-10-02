#!/bin/bash
set -uex

degree=22

params_dir="kzg_params"
mkdir -p "$params_dir"

degree_output_file="$params_dir"/params"${degree}"
rm -f "$degree_output_file"

axel -ac https://trusted-setup-halo2kzg.s3.eu-central-1.amazonaws.com/perpetual-powers-of-tau-raw-"$degree" -o "$degree_output_file"

