package updater_test

// func TestWorkerGetCertsOrTimeout(t *testing.T) {
// 	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Second)
// 	defer cancelF()

// 	// Configure a test DB.
// 	config, removeF := testdb.ConfigureTestDB(t)
// 	defer removeF()

// 	// Connect to the DB.
// 	conn := testdb.Connect(t, config)
// 	defer conn.Close()

// 	manager := &updater.Manager{
// 		MultiInsertSize: 10,
// 	}

// 	worker := updater.NewWorkerForTesting(ctx, manager, conn)
// 	certs := worker.GetCertsOrTimeout(time.Nanosecond)
// 	// Should be empty.
// 	require.Equal(t, 0, len(certs))

// 	// Function to send n certificates to this worker.
// 	send := func(n int) {
// 		for i := 0; i < n; i++ {
// 			worker.IncomingCert <- &updater.Certificate{
// 				Names: []string{
// 					fmt.Sprintf("test %d", i),
// 				},
// 			}
// 		}
// 	}

// 	// Now send some certificates and flush.
// 	go func() {
// 		send(2)
// 		worker.FlushCerts()
// 	}()
// 	t0 := time.Now()
// 	certs = worker.GetCertsOrTimeout(2 * time.Minute)
// 	elapsed := time.Since(t0)
// 	require.Equal(t, 2, len(certs)) // the multi insert size is 10
// 	require.Less(t, elapsed, time.Second)

// 	// Let's send now lots of certs.
// 	go send(11)
// 	t0 = time.Now()
// 	certs = worker.GetCertsOrTimeout(2 * time.Second)
// 	elapsed = time.Since(t0)
// 	require.Equal(t, 10, len(certs)) // the multi insert size
// 	require.Less(t, elapsed, time.Second)
// }
