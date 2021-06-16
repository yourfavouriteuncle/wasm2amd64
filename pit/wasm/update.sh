#!/bin/sh

for wat in *.wat; do
    echo "updating $wat"
    wat2wasm "$wat"
done
