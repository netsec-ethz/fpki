cd ../cmd/PL_logServer
go mod tidy
go build -o PL_logServerExec logServer.go
mv PL_logServerExec ../PL_logServerExec

cd ../PL_logSigner
go mod tidy
go build -o PL_logSignerExec logSigner.go
mv PL_logSignerExec ../PL_logSignerExec