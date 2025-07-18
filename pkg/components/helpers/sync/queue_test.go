package sync

import (
	"sync"
	"testing"
	"time"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/testutil"

	"github.com/stretchr/testify/assert"
)

const timeout = 5 * time.Second

func TestQueueDequeueBlockingIfEmpty(t *testing.T) {
	// GIVEN an empty queue
	q := NewQueue[int]()

	// WHEN dequeuing an element
	available := make(chan int, 30)
	go func() {
		for {
			available <- q.Dequeue()
		}
	}()

	// THEN it blocks until an element is available
	testutil.ChannelEmpty(t, available, 10*time.Millisecond)

	// AND WHEN there are available elements
	q.Enqueue(1)

	// THEN it unblocks and elements are returned in order
	assert.Equal(t, 1, testutil.ReadChannel(t, available, timeout))
}

func TestQueueOrdering(t *testing.T) {
	q := NewQueue[int]()

	go func() {
		for i := 0; i < 1000; i++ {
			q.Enqueue(i)
		}
	}()

	for i := 0; i < 1000; i++ {
		assert.Equal(t, i, q.Dequeue())
	}
}

func TestSynchronization(t *testing.T) {
	q := NewQueue[int]()
	// enqueuing from concurrent goroutines
	for i := 0; i < 1000; i++ {
		cnt := i
		go q.Enqueue(cnt)
	}

	receivedValues := sync.Map{}
	wg := sync.WaitGroup{}
	wg.Add(1000)
	for i := 0; i < 1000; i++ {
		// dequeuing from concurrent goroutines
		go func() {
			receivedValues.Store(q.Dequeue(), struct{}{})
			wg.Done()
		}()
	}

	// wait for all the goroutines to finish
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	testutil.ReadChannel(t, done, timeout)

	// check that each enqueued value has been effectively dequeued
	for i := 0; i < 1000; i++ {
		_, ok := receivedValues.Load(i)
		assert.Truef(t, ok, "expected to receive value %d", i)
	}

	// make sure that the queue is empty
	available := make(chan int)
	go func() {
		available <- q.Dequeue()
	}()
	testutil.ChannelEmpty(t, available, 10*time.Millisecond)
}
