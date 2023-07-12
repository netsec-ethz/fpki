package main

import (
	"context"
	"time"

	db "github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/db/mysql"
	"github.com/netsec-ethz/fpki/pkg/mapserver/responder"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
)

type MapServer struct {
	Responder *responder.MapResponder
	Updater   *updater.MapUpdater
}

func NewMapserver(dbConfig *db.Configuration) (*MapServer, error) {
	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelF()

	// Connect to the DB.
	conn, err := mysql.Connect(dbConfig)
	if err != nil {
		return nil, err
	}

	// Create a responder.
	resp, err := responder.NewMapResponder(ctx, "deleteme", conn)
	if err != nil {
		return nil, err
	}

	// Compose MapServer.
	return &MapServer{
		Responder: resp,
	}, nil
}

func (s *MapServer) Update() error {
	return nil
}
