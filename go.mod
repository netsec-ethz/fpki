module FPKI

go 1.17

replace DomainOwner.FPKI.github.com => /Users/yongzhe/Desktop/fpki/DomainOwner

replace PCA.FPKI.github.com => /Users/yongzhe/Desktop/fpki/PCA

replace common.FPKI.github.com => /Users/yongzhe/Desktop/fpki/common

require (
	DomainOwner.FPKI.github.com v0.0.0-00010101000000-000000000000
	PCA.FPKI.github.com v0.0.0-00010101000000-000000000000
	common.FPKI.github.com v0.0.0-00010101000000-000000000000
	github.com/davecgh/go-spew v1.1.1
)
