#!/bin/bash

if [[ $# -ne 3 ]]; then
    echo "Usage: $0 <circuit_name> <verifier_url> <scheme>"
    exit 1
fi

DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"

prove_circuit(){
    CIRCUIT=$1
    VERIFIER_URL=$2
    SCHEME=$3
    CIRCUIT_DIR=$CIRCUIT
    BYTECODE=$CIRCUIT_DIR/target/$CIRCUIT.json
    WITNESS=$CIRCUIT_DIR/target/$CIRCUIT.gz
    PROOF_DIR=proofs/$1

    echo -e "\n\n*** Proving circuit: $CIRCUIT\n"

    echo -e "*** Gates count\n"
    bb gates $SCHEME -b $BYTECODE | jq -r '.functions[0] | "\(.acir_opcodes),\(.circuit_size)"' >> stats.txt
    bb gates $SCHEME -b $BYTECODE

    echo -e "\n\n*** Create a verifier key\n"
    bb write_vk $SCHEME -b $BYTECODE -o $PROOF_DIR

    echo -e "\n*** Create a proof for the circuit $CIRCUIT\n"
    bb prove $SCHEME -b $BYTECODE -w $WITNESS -k $PROOF_DIR/vk -o $PROOF_DIR

    RESPONSE=$(curl -X POST $VERIFIER_URL \
        -F "proof=@$PROOF_DIR/proof" \
        -F "vk=@$PROOF_DIR/vk" \
        -F "public_inputs=@$PROOF_DIR/public_inputs" \
        -F "scheme=$SCHEME")
    
    echo -e "\n*** Verification response:\n$RESPONSE\n"

    
    VERIFICATION=$(echo "$RESPONSE" | jq -r '.verification')

    if [[ "$VERIFICATION" == "VERIFIED" ]]; then
        echo -e "\n*** Proof verified successfully\n"
        return 0
    else
        echo -e "\n*** Proof verification failed\n"
        exit 1
    fi
}

prove_circuit $1 $2 $3
