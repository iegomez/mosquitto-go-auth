#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd $SCRIPT_DIR

cfssl genkey -initca ca.json | cfssljson -bare ca

# New subcommand so we don't mess up our last cd location
bash -c "./db/generate.sh"
bash -c "./grpc/generate.sh"

cd -