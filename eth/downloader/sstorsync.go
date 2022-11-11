package downloader

import (
	"github.com/ethereum/go-ethereum/log"
	"sync"
)

// sstorState starts downloading sstorage data.
func (d *Downloader) sstorState() *sstorSync {
	s := newSstorSync(d)
	select {
	case d.sstorSyncStart <- s:
		<-s.started
	case <-d.quitCh:
		s.err = errCancelStateFetch
		close(s.done)
	}
	return s
}

// sstorageFetcher manages the active sstorage sync and accepts requests
// on its behalf.
func (d *Downloader) sstorageFetcher() {
	for {
		select {
		case s := <-d.sstorSyncStart:
			for next := s; next != nil; {
				next = d.runSstorSync(next)
			}
		case <-d.quitCh:
			return
		}
	}
}

// runStateSync runs a state synchronisation until it completes or another root
// hash is requested to be switched over to.
func (d *Downloader) runSstorSync(s *sstorSync) *sstorSync {
	log.Warn("--------------------------runSstorSync run-------------------------")
	go s.run()
	defer s.Cancel()

	for {
		select {
		case next := <-d.sstorSyncStart:
			return next

		case <-s.done:
			return nil
		}
	}
}

// sstorSync schedules requests for downloading the latest sstorage content.
type sstorSync struct {
	d *Downloader // Downloader instance to access and manage current peerset

	started    chan struct{} // Started is signalled once the sync loop starts
	cancel     chan struct{} // Channel to signal a termination request
	cancelOnce sync.Once     // Ensures cancel only ever gets called once
	done       chan struct{} // Channel to signal termination completion
	err        error         // Any error hit during sync (set before completion)
}

// newSstorSync creates a new sstorage download scheduler. This method does not
// yet start the sync. The user needs to call run to initiate.
func newSstorSync(d *Downloader) *sstorSync {
	return &sstorSync{
		d:       d,
		cancel:  make(chan struct{}),
		done:    make(chan struct{}),
		started: make(chan struct{}),
	}
}

// run starts the task assignment and response processing loop, blocking until
// it finishes, and finally notifying any goroutines waiting for the loop to
// finish.
func (s *sstorSync) run() {
	close(s.started)
	s.err = s.d.SstorSyncer.Sync(s.cancel)
	close(s.done)
}

// Wait blocks until the sync is done or canceled.
func (s *sstorSync) Wait() error {
	<-s.done
	return s.err
}

// Cancel cancels the sync and waits until it has shut down.
func (s *sstorSync) Cancel() error {
	s.cancelOnce.Do(func() {
		close(s.cancel)
	})
	return s.Wait()
}
