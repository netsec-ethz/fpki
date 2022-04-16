package policyLog

import (
	"fmt"
	//"github.com/google/trillian"
	"github.com/google/trillian/client/rpcflags"
)

func GetAllTrees() error {
	_, err := rpcflags.NewClientDialOptionsFromFlags()
	if err != nil {
		return fmt.Errorf("GetAllTrees | NewClientDialOptionsFromFlags | %s", err.Error())
	}

	return nil
}
