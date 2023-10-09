#!/bin/bash
# Start log server

./tools/create_schema.sh

./bin/logserver_exec >/dev/null& 

# Start log signer
./bin/logsigner_exec >/dev/null& 

PCA_EXIT_CPDE="succeed"
POLICY_EXIT_CPDE="succeed"
MAP_EXIT_CPDE="succeed"
SMT_EXIT_CPDE="succeed"
GRPC_EXIT_CPDE="succeed"

RESULT="succeed"

sleep 2
# run tests
echo "#################    Running domainowner_pca_policlog_interaction     ###################"
./bin/test_domainowner_pca_policlog_interaction 
if [ $? -ne 0 ]
then
	PCA_EXIT_CPDE="failed"
fi
echo "#################         Running policylog_interaction               ###################"
./bin/test_policylog_interaction
if [ $? -ne 0 ]
then
	POLICY_EXIT_CPDE="failed"
fi
echo "#################         Running mapserver   test                 ###################"
./bin/test_mapserver
if [ $? -ne 0 ]
then
	MAP_EXIT_CPDE="failed"
fi
echo "#################         Running smt test                    ###################"
./bin/test_smt
if [ $? -ne 0 ]
then
	SMT_EXIT_CPDE="failed"
fi

echo "#################         Running grpc test                    ###################"
./bin/test_grpc
if [ $? -ne 0 ]
then
	GRPC_EXIT_CPDE="failed"
fi

echo " ##################################   Integration test results:  #################################    "
echo " Test: domainowner_pca_policlog_interaction:        ${PCA_EXIT_CPDE}"
echo " Test: policylog_interaction:                       ${POLICY_EXIT_CPDE}"
echo " Test: mapserver:                                   ${MAP_EXIT_CPDE}"
echo " Test: sparse merkle tree:                          ${SMT_EXIT_CPDE}"
echo " Test: grpc:                                        ${GRPC_EXIT_CPDE}"

echo " **********************************     Overall Result      ***************************************    "
if [ $PCA_EXIT_CPDE != "succeed" ] || [ $POLICY_EXIT_CPDE != "succeed" ] ||
   [ $MAP_EXIT_CPDE != "succeed" ] || [ $SMT_EXIT_CPDE != "succeed" ] ||
   [ $GRPC_EXIT_CPDE != "succeed" ]
then
	RESULT="failed"
fi
echo " ${RESULT}"
echo " **************************************************************************************************   "
# stop log
# looks like kill once is not enough... do this for now
pkill -f logserver_exec
pkill -f logsigner_exec
pkill -f logserver_exec
pkill -f logsigner_exec
