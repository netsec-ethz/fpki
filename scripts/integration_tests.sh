#!/bin/bash
# Start log server

./bin/logserver_exec >/dev/null& 

# Start log signer
./bin/logsigner_exec >/dev/null& 

sleep 2
# run tests
echo "#################    Running domainowner_pca_policlog_interaction     ###################"
./bin/test_domainowner_pca_policlog_interaction 
echo "#################         Running policylog_interaction               ###################"
./bin/test_policylog_interaction
echo "#################         Running mapserver   test                 ###################"
./bin/test_mapserver
echo "#################         Running smt test                    ###################"
./bin/test_smt
echo "#################         Running db test                    ###################"
./bin/test_db


# stop log
pkill -f logserver_exec
pkill -f logsigner_exec
