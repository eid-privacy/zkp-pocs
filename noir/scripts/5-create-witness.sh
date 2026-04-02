#!/bin/bash

DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"

for circuit in [cd]??_*; do
    if [ -f $circuit/Nargo.toml ]; then
      echo "Executing circuit $circuit"
      prover=$([ -f $circuit/Prover_0.toml ] && echo Prover_0.toml || echo Prover.toml)
      (cd $circuit && pwd && $DIR/time_real.sh nargo execute -p $prover)
    fi
done
