#!/bin/bash

DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"

if [[ $# -ne 4 ]]; then
    echo "Usage: $0 <proof_file> <vk_file> <public_inputs_file> <scheme>"
    exit 1
fi

PROOF_FILE="$1"
VK_FILE="$2"
PUBLIC_INPUTS_FILE="$3"
SCHEME="$4"

echo "Verifying:"
echo "  proof:          $PROOF_FILE"
echo "  vk:             $VK_FILE"
echo "  public_inputs:  $PUBLIC_INPUTS_FILE"
echo "  scheme:         $SCHEME"

bb verify \
    $SCHEME \
    -p "$PROOF_FILE" \
    -k "$VK_FILE" \
    -i "$PUBLIC_INPUTS_FILE"