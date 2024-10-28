.PHONY: all clean test policy_log jaeger-start jaeger-stop

all: build_mapserver build_ingest build_policy_log build_integration_test

clean:
	@rm -f bin/*

test:
	@go test ./...
	@echo "Tests OK"

integration: build_integration_test
	@# ./bin/test_policylog_interaction
	@# ./bin/test_smt
	./bin/test_mapserver
	@echo "All integration tests OK"

build_mapserver:
	@go build -o bin/mapserver ./cmd/mapserver/

build_ingest:
	@go build -o bin/ingest ./cmd/ingest/

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

mockgen:
	@echo "mockgen version `mockgen --version`" || (\
		echo "Run 'go install go.uber.org/mock/mockgen@latest' to install mockgen"; \
		echo "See also: https://github.com/uber-go/mock"; \
		exit 1; \
	)
	@# for each mock location:
	@cd ./pkg/db && mockgen -destination ./mock_db/conn.go  . Conn

jaeger-start:
	@docker run -d --rm --name jaeger \
	   -e COLLECTOR_ZIPKIN_HOST_PORT=:9411 \
	   -e COLLECTOR_OTLP_ENABLED=true \
	   -p 6831:6831/udp \
	   -p 6832:6832/udp \
	   -p 5778:5778 \
	   -p 16686:16686 \
	   -p 4317:4317 \
	   -p 4318:4318 \
	   -p 14250:14250 \
	   -p 14268:14268 \
	   -p 14269:14269 \
	   -p 9411:9411 \
	   jaegertracing/all-in-one:1.62.0
	@# or jaegertracing/all-in-one:latest

jaeger-start-shorter:
	@docker run -d --rm --name jaeger \
		-e COLLECTOR_OTLP_ENABLED=true \
		-p 16686:16686 \
		-p 4317:4317 \
		-p 4318:4318 \
		jaegertracing/all-in-one:latest

jaeger-stop:
	@docker stop jaeger

jaeger-restart:
	@$(MAKE) jaeger-stop
	@$(MAKE) jaeger-start
