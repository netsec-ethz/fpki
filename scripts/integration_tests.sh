# Start log server
./bin/logserver_exec >/dev/null& 

# Start log signer
./bin/logsigner_exec >/dev/null& 

sleep 2
# run tests
echo "#################    Running domainowner_pca_policlog_interaction     ###################"
./bin/domainowner_pca_policlog_interaction 
echo "#################         Running policylog_interaction               ###################"
./bin/policylog_interaction
echo "#################         Running mapserver   test                 ###################"
./bin/mapserver
echo "#################         Running smt test                    ###################"
./bin/smt
echo "#################         Running updater test                    ###################"
./bin/updater
echo "#################         Running db test                    ###################"
./bin/db


# stop log
pkill -f logserver_exec
pkill -f logsigner_exec
