cd test/common_test
go mod tidy
go test -v

cd ../PCA_DomainOwner_Interaction_test
go mod tidy
go test -v