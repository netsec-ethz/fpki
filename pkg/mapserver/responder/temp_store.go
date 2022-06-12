package responder

// TODO(yongzhe): cache frequently visited domains here, for better performance

type TempStore struct {
}

func newTempStore() *TempStore {
	return &TempStore{}
}
