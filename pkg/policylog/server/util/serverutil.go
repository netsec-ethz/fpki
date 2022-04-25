// Copyright 2017 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package serverutil holds code for running Trillian servers.
package util

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/golang/glog"
	"github.com/google/trillian"
	"github.com/google/trillian/extension"
	"github.com/google/trillian/monitoring"
	"github.com/google/trillian/server/admin"
	"github.com/google/trillian/server/interceptor"
	"github.com/google/trillian/util/clock"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
)

// Main encapsulates the data and logic to start a Trillian server (Log or Map).
type Main struct {
	// Endpoints for RPC and HTTP servers.
	// HTTP is optional, if empty it'll not be bound.
	RPCEndpoint, HTTPEndpoint string

	// TLS Certificate and Key files for the server.
	TLSCertFile, TLSKeyFile string

	DBClose func() error

	Registry extension.Registry

	StatsPrefix string
	QuotaDryRun bool

	// RegisterServerFn is called to register RPC servers.
	RegisterServerFn func(*grpc.Server, extension.Registry) error

	// IsHealthy will be called whenever "/healthz" is called on the mux.
	// A nil return value from this function will result in a 200-OK response
	// on the /healthz endpoint.
	IsHealthy func(context.Context) error
	// HealthyDeadline is the maximum duration to wait wait for a successful
	// IsHealthy() call.
	HealthyDeadline time.Duration

	// AllowedTreeTypes determines which types of trees may be created through the Admin Server
	// bound by Main. nil means unrestricted.
	AllowedTreeTypes []trillian.TreeType

	TreeGCEnabled         bool
	TreeDeleteThreshold   time.Duration
	TreeDeleteMinInterval time.Duration

	// These will be added to the GRPC server options.
	ExtraOptions []grpc.ServerOption
}

// Run starts the configured server. Blocks until the server exits.
func (m *Main) Run(ctx context.Context) error {
	glog.CopyStandardLogTo("WARNING")

	if m.HealthyDeadline == 0 {
		m.HealthyDeadline = 5 * time.Second
	}

	srv, err := m.newGRPCServer()
	if err != nil {
		glog.Exitf("Error creating gRPC server: %v", err)
	}
	defer srv.GracefulStop()

	defer m.DBClose()

	if err := m.RegisterServerFn(srv, m.Registry); err != nil {
		return err
	}
	trillian.RegisterTrillianAdminServer(srv, admin.New(m.Registry, m.AllowedTreeTypes))
	reflection.Register(srv)

	g, ctx := errgroup.WithContext(ctx)

	glog.Infof("RPC server starting on %v", m.RPCEndpoint)
	lis, err := net.Listen("tcp", m.RPCEndpoint)
	if err != nil {
		return err
	}

	if m.TreeGCEnabled {
		g.Go(func() error {
			glog.Info("Deleted tree GC started")
			gc := admin.NewDeletedTreeGC(
				m.Registry.AdminStorage,
				m.TreeDeleteThreshold,
				m.TreeDeleteMinInterval,
				m.Registry.MetricFactory)
			gc.Run(ctx)
			return nil
		})
	}

	run := func() error {
		if err := srv.Serve(lis); err != nil {
			return fmt.Errorf("RPC server terminated: %v", err)
		}

		return nil
	}

	shutdown := func() {
		glog.Infof("Stopping RPC server...")
		glog.Flush()

		srv.GracefulStop()
	}

	g.Go(func() error {
		return srvRun(ctx, run, shutdown)
	})

	// wait for all jobs to exit gracefully
	err = g.Wait()

	// Give things a few seconds to tidy up
	time.Sleep(time.Second * 5)

	return err
}

// newGRPCServer starts a new Trillian gRPC server.
func (m *Main) newGRPCServer() (*grpc.Server, error) {
	stats := monitoring.NewRPCStatsInterceptor(clock.System, m.StatsPrefix, m.Registry.MetricFactory)
	ti := interceptor.New(m.Registry.AdminStorage, m.Registry.QuotaManager, m.QuotaDryRun, m.Registry.MetricFactory)

	serverOpts := []grpc.ServerOption{
		grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(
			stats.Interceptor(),
			interceptor.ErrorWrapper,
			ti.UnaryInterceptor,
		)),
	}
	serverOpts = append(serverOpts, m.ExtraOptions...)

	// Let credentials.NewServerTLSFromFile handle the error case when only one of the flags is set.
	if m.TLSCertFile != "" || m.TLSKeyFile != "" {
		serverCreds, err := credentials.NewServerTLSFromFile(m.TLSCertFile, m.TLSKeyFile)
		if err != nil {
			return nil, err
		}
		serverOpts = append(serverOpts, grpc.Creds(serverCreds))
	}

	s := grpc.NewServer(serverOpts...)

	return s, nil
}

func (m *Main) healthz(rw http.ResponseWriter, req *http.Request) {
	if m.IsHealthy != nil {
		ctx, cancel := context.WithTimeout(req.Context(), m.HealthyDeadline)
		defer cancel()
		if err := m.IsHealthy(ctx); err != nil {
			rw.WriteHeader(http.StatusServiceUnavailable)
			rw.Write([]byte(err.Error()))
			return
		}
	}
	rw.Write([]byte("ok"))
}

// srvRun run the server and call `shutdown` when the context has been cancelled
func srvRun(ctx context.Context, run func() error, shutdown func()) error {
	exit := make(chan struct{})
	var err error
	go func() {
		defer close(exit)
		err = run()
	}()

	select {
	case <-ctx.Done():
		shutdown()
		// wait for run to return
		<-exit
	case <-exit:
	}

	return err
}
