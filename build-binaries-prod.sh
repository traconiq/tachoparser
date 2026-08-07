#!/usr/bin/env bash

set -e -u -o pipefail

export GOFLAGS="-buildvcs=false"

readonly BINARIES=(cmd/dddparser cmd/dddserver cmd/dddclient cmd/dddui cmd/dddsimple cmd/dddscan)

(cd ./scripts/pks1/ && ./dl_all_pks1.py)
(cd ./scripts/pks2/ && ./dl_all_pks2.py)

go mod vendor

for bin in ${BINARIES[@]}; do
    echo "Building $bin"
    (cd ./${bin}/ && go build .)
done
