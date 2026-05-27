#!/bin/bash

SCHEME=""
DIR="../scripts/"
CIRCUIT="d11_sicpa_backend"
BYTECODE="target/$CIRCUIT.json"
WITNESS="target/$CIRCUIT.gz"
PROOF_DIR="proof"

echo -e "*** Gates count\n"
bb gates $SCHEME -b $BYTECODE | jq -r '.functions[0] | "\(.acir_opcodes),\(.circuit_size)"' >> stats.txt
bb gates $SCHEME -b $BYTECODE

echo -e "\n\n*** Create a verifier key\n"
$DIR/time_real.sh bb write_vk $SCHEME -b $BYTECODE -o $PROOF_DIR

echo -e "\n*** Create a proof for the circuit $CIRCUIT\n"
$DIR/time_real.sh bb prove $SCHEME -b $BYTECODE -w $WITNESS -k $PROOF_DIR/vk -o $PROOF_DIR

echo -e "\n*** Verify the created proof\n"
$DIR/time_real.sh bb verify $SCHEME -p $PROOF_DIR/proof -k $PROOF_DIR/vk -i $PROOF_DIR/public_inputs
