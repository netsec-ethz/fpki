.PHONY: all clean test policy_log

all: build_policy_log build_integration_test build_benchmark

clean:
	@rm -f bin/*

test:
	@go test ./...

build_policy_log:
	@go build -o bin/logserver_exec cmd/logserver/logserver_exec.go
	@go build -o bin/logsigner_exec cmd/logsigner/logsigner_exec.go

setup_db: start_db create_smt_database create_log_database create_tables

start_db:
	@mysql.server start

create_smt_database:
	@mysql -u root -e "CREATE SCHEMA IF NOT EXISTS \`map\`;"

create_tables:
	@mysql -u root -e "CREATE TABLE IF NOT EXISTS \`map\`.\`cacheStore\` (\`key\` VARCHAR(64) NOT NULL,\`value\` VARCHAR(2048) NOT NULL, PRIMARY KEY (\`key\`));"
	@mysql -u root -e "CREATE TABLE IF NOT EXISTS \`map\`.\`deleteTest\` (\`key\` VARCHAR(64) NOT NULL,\`value\` VARCHAR(2048) NOT NULL, PRIMARY KEY (\`key\`));"
	@mysql -u root -e "CREATE TABLE IF NOT EXISTS \`map\`.\`domainEntries\` (\`key\` VARCHAR(64) NOT NULL,\`value\` LONGTEXT NOT NULL, PRIMARY KEY (\`key\`));"
	@mysql -u root -e "CREATE TABLE IF NOT EXISTS \`map\`.\`updatedDomains\` (\`domainHash\` VARCHAR(64) NOT NULL, PRIMARY KEY (\`domainHash\`));"

create_log_database:
	@./scripts/reset_db/resetdb.sh



build_integration_test:
	@go build -o ./bin/policylog_interaction  ./tests/intergration_tests/policylog_interaction
	@go build -o ./bin/domainowner_pca_policlog_interaction  ./tests/intergration_tests/domainowner_pca_policlog_interaction
	@go build -o ./bin/mapserver  ./tests/intergration_tests/mapserver
	@go build -o ./bin/smt  ./tests/intergration_tests/smt
	@go build -o ./bin/log_picker  ./tests/intergration_tests/log_picker

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