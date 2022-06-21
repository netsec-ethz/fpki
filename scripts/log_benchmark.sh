#!/bin/bash

./tools/create_schema.sh

# Start log server
./bin/logserver_exec >/dev/null& 

# Start log signer
./bin/logsigner_exec >/dev/null& 

# run tests
sleep 2
./bin/log_benchmark

# stop log
pkill -f logserver_exec
pkill -f logsigner_exec
pkill -f logserver_exec
pkill -f logsigner_exec
