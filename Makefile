.PHONY: all clean test policy_log

all: policy_log build_integration_test

clean:
	@rm -f bin/*

test:
	@go test ./...

policy_log:
	@go build -o bin/logserver_exec cmd/logserver/logserver_exec.go
	@go build -o bin/logsigner_exec cmd/logsigner/logsigner_exec.go

create_database:
	@mysql -u root -e "create database map;"

reset_tables:
	@mysql -u root -e "DROP TABLE map.node;"
	@mysql -u root -e "DROP TABLE map.value;"

build_integration_test:
	@go build -o ./bin/policylog_interaction  ./tests/intergration_tests/policylog_interaction
	@go build -o ./bin/domainowner_pca_policlog_interaction  ./tests/intergration_tests/domainowner_pca_policlog_interaction
	@go build -o ./bin/mapserver  ./tests/intergration_tests/mapserver
	@go build -o ./bin/smt  ./tests/intergration_tests/smt

drop_cacheTable:
	@mysql -u root -e "DROP TABLE map.deleteTest;"

run_integration_test:
	@./scripts/integration_tests.sh

build_benchmark:
	@go build -o ./bin/log_benchmark  ./tests/benchmark/logserver_benchmark
	@go build -o ./bin/smt_benchmark  ./tests/benchmark/smt_benchmark

run_log_benchmark:
	@./scripts/log_benchmark.sh

run_smt_benchmark:
	@./bin/smt_benchmark