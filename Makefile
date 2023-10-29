.PHONY: all clean test policy_log

all: build_mapserver build_policy_log build_integration_test

clean:
	@rm -f bin/*

test:
	@go test ./...

integration: build_integration_test
	@# ./bin/test_policylog_interaction
	@# ./bin/test_smt
	./bin/test_mapserver
	@echo "All integration tests OK"

build_mapserver:
	@go build -o bin/mapserver ./cmd/mapserver/

build_policy_log:
	@go build -o bin/logserver_exec cmd/logserver/logserver_exec.go
	@go build -o bin/logsigner_exec cmd/logsigner/logsigner_exec.go

create_fpki_schema_replace_old:
	@./tools/create_schema.sh

build_integration_test:
	@# @go build -o ./bin/test_policylog_interaction  ./tests/integration/policylog_interaction
	@# @go build -o ./bin/test_smt  ./tests/integration/smt
	@go build -o ./bin/test_mapserver ./tests/integration/mapserver/

drop_cacheTable:
	@mysql -u root -e "DROP TABLE map.deleteTest;"
