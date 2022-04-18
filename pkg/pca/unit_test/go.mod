module unit_test

go 1.17

replace pca.FPKI.github.com => /Users/yongzhe/Desktop/fpki/pkg/pca

replace common.FPKI.github.com => /Users/yongzhe/Desktop/fpki/pkg/common

replace logverifier.FPKI.github.com => /Users/yongzhe/Desktop/fpki/pkg/logVerifier

require pca.FPKI.github.com v0.0.0-00010101000000-000000000000

require (
	common.FPKI.github.com v0.0.0-00010101000000-000000000000 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/certificate-transparency-go v1.1.2-0.20210512142713-bed466244fa6 // indirect
	github.com/google/trillian v1.4.0 // indirect
	github.com/transparency-dev/merkle v0.0.0-20220411132142-cfdaeb1822ee // indirect
	golang.org/x/net v0.0.0-20210503060351-7fd8e65b6420 // indirect
	golang.org/x/sys v0.0.0-20210806184541-e5e7981a1069 // indirect
	golang.org/x/text v0.3.6 // indirect
	google.golang.org/genproto v0.0.0-20210821163610-241b8fcbd6c8 // indirect
	google.golang.org/grpc v1.40.0 // indirect
	google.golang.org/protobuf v1.27.1 // indirect
	logverifier.FPKI.github.com v0.0.0-00010101000000-000000000000 // indirect
)
