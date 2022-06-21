# FPKI

## Features

- Issuance and logging of RPC (Root Policy Certificate)
- Issuance of SPT (Signed Policy Certificate) using RPC
- Verification of RPC using SPT
- Consistency verification of the log

## Dir structure

    .
    ├── cert                                  # certificates for testing. Eg. cert for PCA
    ├── cmd                                   # Executables. Log server and log signer
    ├── config                                # Config file for PCA and policy log
    ├── doc                                   # FPKI design
    │   ├── images
    │   └── performance_test_output           # Some results of the policy log performance
    ├── pkg                                   # Packages of the project
    ├── scripts                               # Scripts to clean and build the executables
    └── tests                                 # Some intergration tests. Unit tests are in the individual pkg 
    
    
 ## Overview
 ![Alt text](doc/images/overview.png?raw=true"Overview")
 
 The figure above illustrates the components so far. The domain owner sends RCSR to the PCA, and PCA signs the RCSR to generate an RPC. Then the PCA sends the RPC to the policy log to get an SPT. The log verifier will verify the SPT and the consistency between the old tree head and the newest tree head.
 
 ### Policy log
 Trillian is used in the policy log.

 The policy log is the most complex component so far. It consists of four sub-components:
 - **(Log server)** Log server is responsible for receiving and sending responses. However, it does not generate proof of inclusion. It is similar to a user interface, which handles the RPC request and distributes the result.
 - **(Log signer)** Log signer is responsible for adding the new leaves, generating the new tree head, and the proof of inclusion for every added leaf. 
 - **(Log client)** Log client is responsible for sending the new leaves to the log server and retrieving information from the log server.
 - **(Admin client)** Admin client is responsible for managing trees in the log server. For example, create a new tree or delete an existing tree.
 
Within the policy log, the log client and admin client only communicate with the log server via grpc. Log signer only communicates with the log server, and the communication is internal, so we don't have access to it. For other components outside the policy log, they can only have access to the log client to add leaves of fetch proof of inclusion. Admin client should only be accessed internally.

## How to run the integration tests
There are two integration tests which require the setup of Trillian server.

Download trillian and setup database (more information on https://github.com/google/trillian#mysql-setup)
```
git clone https://github.com/google/trillian.git
cd scripts
./resetdb.sh
```
Download the FPKI

Conpile the executable
 ```
   make
   make test_folders
 ```
 
 Open two terminals, run "cmd/logserver_exec" and "cmd/logsigner_exec"
 
 Run the tests:
  ```
   cd fpki
   go test ./...
 ```
 

## Integration tests and benchmark
There are some integration tests and benchmark under the tests folders.

    .
    ├── benchmark                                  # benchmark for each components
    │  ├── db_benchmark
    │  └── logserver_benchmark           
    │  └── smt_benchmark          
    │  └── mapserver_benchmark 
    │  │  └── updater_benchmark    
    │  │  └── responder_benchmark           
    ├── integration_tests  
    │  └── db    
    │  └── domainowner_pca_policy_interaction    
    │  └── mapserver    
    │  └── policy_interaction                                    
    │  └── smt   
    
For map server, you might be interested in the following tests:
### Benchmark/db_benchmark

This benchmark evaluates the inserting speed, reading speed and deleting speed of a key-value store.

### Benchmark/smt_benchmark

This benchmark evaluates the speed of Sparse Merkle Tree. For example, the updating speed of SMT, and time to commit the changes to the DB. 

### Benchmark/mapserver_benchmark
 
This folder contains two folders, one for updater and one for responder. The updater is responsible for updating the SMT and changing the domain entries table. The responder is responsible for generating the proof, and distributing the proof to client. Currently, the updater and responder are evaluated seperately. If you want to combine the two benchmarks together, please send me a message and I can do some modification. It's trivial. 

### integration_tests/mapserver

domain materials: Bytes which contain all the certificates which are related to this domain name.

This test is the integration test for mapserver. The test first starts an updater, fetches 1000 certificates from CT log, and adds them to the SMT and domain entries tables. Then the test starts a responder, re-collects the previously-added certificates, and queries the proof for corresponding domain name. Then the proof is checked against individual certificate(whether the certificate is included in the domain materials, and whether SMT proof is correct). 