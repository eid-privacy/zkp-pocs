#!/bin/bash

DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"

for circuit in c??_*; do
    if [ -f $circuit/Nargo.toml ]; then
      echo "Executing circuit $circuit"
      (cd $circuit && nargo compile && pwd && $DIR/time_real.sh nargo execute -p Prover_0.toml)
    fi
done
