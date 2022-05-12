# Start log server
./bin/logserver_exec >/dev/null& 

# Start log signer
./bin/logsigner_exec >/dev/null& 

# run tests
echo "#################    Running domainowner_pca_policlog_interaction     ###################"
./bin/domainowner_pca_policlog_interaction 
echo "#################         Running policylog_interaction               ###################"
./bin/policylog_interaction
echo "#################         Running mapserver   test                 ###################"
./bin/mapserver
echo "#################         Running smt test                    ###################"
./bin/smt

# stop log
pkill -f logserver_exec
pkill -f logsigner_exec
