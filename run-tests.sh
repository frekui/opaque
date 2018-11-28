#!/bin/bash

set -ex

go vet
go test ./...
go build ./cmd/server
go build ./cmd/client

./server > server.log &
serverpid=$!
cleanup() {
    if [ "$test_ok" != 1 ];
    then
	echo Test failed.
    fi
    kill $serverpid
}
trap cleanup EXIT
sleep 1

./client -pwreg -username foo -password bar > client-reg.log
grep "Added user 'foo'" server.log || exit 1

./client -auth -username foo -password bar > client-ok.log
sleep 1
fgrep "Received 'Hi client!'" client-ok.log > /dev/null
fgrep "Sending 'Hi server!'" client-ok.log > /dev/null
fgrep "Received 'Hi server!'" server.log > /dev/null
fgrep "Sending 'Hi client!'" server.log > /dev/null

./client -auth -username foo -password wrong >& client-not-ok.log && exit 1
fgrep "auth: Authtag mismatch" client-not-ok.log > /dev/null

set +x
test_ok=1
echo Test successful.
