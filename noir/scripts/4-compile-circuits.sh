#!/bin/bash

DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"

for circuit in c??_*; do
    if [ -f $circuit/Nargo.toml ]; then
      echo "Compiling circuit $circuit"
      (cd $circuit && nargo compile)
    fi
done