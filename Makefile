.PHONY: all clean test policy_log

all: build_policy_log build_integration_test build_benchmark

clean:
	@rm -f bin/*

test:
	@go test ./...

build_policy_log:
	@go build -o bin/logserver_exec cmd/logserver/logserver_exec.go
	@go build -o bin/logsigner_exec cmd/logsigner/logsigner_exec.go

setup_db: create_log_database create_fpki_table

create_fpki_schema_replace_old:
	@./tools/create_schema.sh

create_log_database:
	@./scripts/reset_db/resetdb.sh

build_integration_test:
	@go build -o ./bin/test_policylog_interaction  ./tests/integration/policylog_interaction
	@go build -o ./bin/test_domainowner_pca_policlog_interaction  ./tests/integration/domainowner_pca_policlog_interaction
	@go build -o ./bin/test_mapserver  ./tests/integration/mapserver
	@go build -o ./bin/test_smt  ./tests/integration/smt
	@go build -o ./bin/test_db  ./tests/integration/db
	@go build -o ./bin/test_grpc  ./tests/integration/grpc_test

drop_cacheTable:
	@mysql -u root -e "DROP TABLE map.deleteTest;"

run_integration_test:
	@./scripts/integration_tests.sh

build_benchmark:
	@go build -o ./bin/log_benchmark  ./tests/benchmark/logserver_benchmark
	@go build -o ./bin/smt_benchmark  ./tests/benchmark/smt_benchmark
	@go build -o ./bin/db_benchmark  ./tests/benchmark/db_benchmark
	@go build -o ./bin/updater_benchmark  ./tests/benchmark/mapserver_benchmark/updater_benchmark
	@go build -o ./bin/responder_benchmark  ./tests/benchmark/mapserver_benchmark/responder_benchmark

run_log_benchmark:
	@./scripts/log_benchmark.sh

run_smt_benchmark:
	@./bin/smt_benchmark

run_db_benchmark:
	@./bin/db_benchmark

run_updater_benchmark:
	@./bin/updater_benchmark

run_responder_benchmark:
	@./bin/responder_benchmark