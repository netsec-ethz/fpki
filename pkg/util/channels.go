package util

import "sync"

// SendToAllChannels sends the value to all channels in parallel, and waits for its reception
// by all of them.
func SendToAllChannels[T any](channels []chan T, value T) {
	wg := sync.WaitGroup{}
	wg.Add(len(channels))
	for _, ch := range channels {
		ch := ch
		go func() {
			defer wg.Done()
			ch <- value
		}()
	}
	wg.Wait()
}
