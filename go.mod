module fpki

go 1.17

replace github.com/netsec-ethz/fpki => ./

require (
	github.com/golang/glog v1.0.0
	github.com/google/trillian v1.4.0
	github.com/grpc-ecosystem/go-grpc-middleware v1.3.0
	github.com/netsec-ethz/fpki v0.0.0-00010101000000-000000000000
	github.com/stretchr/testify v1.7.0
	github.com/transparency-dev/merkle v0.0.0-20220411132142-cfdaeb1822ee
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	google.golang.org/grpc v1.46.0
	google.golang.org/protobuf v1.28.0
)
