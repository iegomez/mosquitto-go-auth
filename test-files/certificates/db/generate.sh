#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd $SCRIPT_DIR

cfssl genkey -initca ca.json | cfssljson -bare ca
cfssl sign -ca ../ca.pem -ca-key ../ca-key.pem -config=profiles.json -profile=ca ca.csr | cfssljson -bare ca
cfssl gencert -ca ca.pem -ca-key ca-key.pem -config=profiles.json -profile=server server.json | cfssljson -bare server
cfssl gencert -ca ca.pem -ca-key ca-key.pem -config=profiles.json -profile=client client.json | cfssljson -bare client
cfssl gencert -ca ca.pem -ca-key ca-key.pem -config=profiles.json -profile=client unauthorized-second-client.json | cfssljson -bare unauthorized-second-client

cat server.pem > fullchain-server.pem
cat ca.pem >> fullchain-server.pem
cat ../ca.pem >> fullchain-server.pem

cat client.pem > fullchain-client.pem
cat ca.pem >> fullchain-client.pem
cat ../ca.pem >> fullchain-client.pem

cd -
