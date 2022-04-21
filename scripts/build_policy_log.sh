cd ../
go mod tidy

go build -o ./cmd/logserver_exec ./cmd/logserver/logserver_exec.go
go build -o ./cmd/logsigner_exec ./cmd/logsigner/logsigner_exec.go