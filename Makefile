.PHONY: all clean policy_log test_folders


all: policy_log

clean:
	@rm -f bin/logserver_exec
	@rm -f bin/logsigner_exec

	@rm -f tests/intergration_tests/policylog_interaction/testdata/output/trees_config/*
	@rm -f tests/intergration_tests/domainowner_pca_policlog_interaction/file_exchange/policylog/logRoot/*
	@rm -f tests/intergration_tests/domainowner_pca_policlog_interaction/file_exchange/policylog/spt/*
	@rm -f tests/intergration_tests/domainowner_pca_policlog_interaction/file_exchange/policylog/trees_config/*
	@rm -f tests/intergration_tests/domainowner_pca_policlog_interaction/file_exchange/pcaoutput/rpc/*
	@rm -f pkg/common/testdata/*.json
	@rm -r tests/intergration_tests/performance_test/testdata/trees_config
	@find . -name ".DS_Store" -delete
	@rm -f pkg/policylog/server/logserver/logserver_config.json

policy_log:
	@go build -o bin/logserver_exec cmd/logserver/logserver_exec.go
	@go build -o bin/logsigner_exec cmd/logsigner/logsigner_exec.go
	@cp config/logserver_config.json bin/logserver_config.json
	@cp config/logsigner_config.json bin/logsigner_config.json

test_folders:
	@mkdir -p tests/intergration_tests/policylog_interaction/testdata/output/trees_config/
	@mkdir -p tests/intergration_tests/domainowner_pca_policlog_interaction/file_exchange/policylog/logRoot/
	@mkdir -p tests/intergration_tests/domainowner_pca_policlog_interaction/file_exchange/policylog/spt/
	@mkdir -p tests/intergration_tests/domainowner_pca_policlog_interaction/file_exchange/policylog/trees_config/
	@mkdir -p tests/intergration_tests/domainowner_pca_policlog_interaction/file_exchange/pcaoutput/rpc/
	@mkdir -p tests/intergration_tests/performance_test/testdata/trees_config/

cerate_database:
	@mysql -u root -e "create database map;"

reset_tables:
	@mysql -u root -e "DROP TABLE map.node;"
	@mysql -u root -e "DROP TABLE map.value;"