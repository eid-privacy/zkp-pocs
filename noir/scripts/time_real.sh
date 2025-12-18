#!/bin/bash

DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
$DEVBOX_PACKAGES_DIR/bin/time -f %e -o $DIR/../stats.txt -a $@
