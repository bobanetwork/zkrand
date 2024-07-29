#!/bin/bash
set -uex

echo "THRESHOLD: ${THRESHOLD}"
echo "NUMBER_OF_MEMBERS: ${NUMBER_OF_MEMBERS}"
echo "DEGREE: ${DEGREE}"

params_dir="kzg_params"
degree_output_file="$params_dir/params${DEGREE}"

# Check if the file already exists
if [ -f "$degree_output_file" ]; then
    echo "File $degree_output_file already exists. Skipping download."
else
    # If the file does not exist, proceed with the download
    echo "File $degree_output_file does not exist. Downloading..."
    # Use curl with error handling
    if curl -f -o "$degree_output_file" "https://axiom-crypto.s3.amazonaws.com/challenge_0085/kzg_bn254_${DEGREE}.srs"; then
        echo "Download completed."
    else
        echo "Download failed." >&2
        exit 1
    fi
fi

RUST_LOG=info THRESHOLD=$THRESHOLD NUMBER_OF_MEMBERS=$NUMBER_OF_MEMBERS DEGREE=$DEGREE ./target/release/client setup --skip

# Touch a health check file to indicate readiness
touch "$params_dir/health_check_${THRESHOLD}_${NUMBER_OF_MEMBERS}_${DEGREE}"

# Execute the main command or default to shell
exec "$@"