#!/bin/bash

SCHEME=""
DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"

prove_circuit(){
    CIRCUIT=$1
    CIRCUIT_DIR=$CIRCUIT
    BYTECODE=$CIRCUIT_DIR/target/$CIRCUIT.json
    WITNESS=$CIRCUIT_DIR/target/$CIRCUIT.gz
    PROOF_DIR=proofs/$1

    echo -e "\n\n*** Proving circuit: $CIRCUIT\n"

    echo -e "*** Gates count\n"
    bb gates $SCHEME -b $BYTECODE | jq -r '.functions[0] | "\(.acir_opcodes),\(.circuit_size)"' >> stats.txt
    bb gates $SCHEME -b $BYTECODE

    echo -e "\n\n*** Create a verifier key\n"
    $DIR/time_real.sh bb write_vk $SCHEME -b $BYTECODE -o $PROOF_DIR

    echo -e "\n*** Create a proof for the circuit $CIRCUIT\n"
    $DIR/time_real.sh bb prove $SCHEME -b $BYTECODE -w $WITNESS -k $PROOF_DIR/vk -o $PROOF_DIR

    echo -e "\n*** Verify the created proof\n"
    $DIR/time_real.sh bb verify $SCHEME -p $PROOF_DIR/proof -k $PROOF_DIR/vk -i $PROOF_DIR/public_inputs

	cat $PROOF_DIR/proof | wc -c >> stats.txt
}

c03_holder_binding,0.17,0.46,0.02,16224

echo "test,acir,circuit,create_vk,create_proof,verify,proof_size" > stats.csv

for circuit in c??_*; do
    echo "$circuit" > stats.txt
    prove_circuit $circuit
    paste -sd, stats.txt >> stats.csv
done
