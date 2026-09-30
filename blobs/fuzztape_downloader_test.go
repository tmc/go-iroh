package blobs

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"io"
	"slices"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/tmc/go-iroh/internal/fuzztape"
	"github.com/tmc/go-iroh/internal/fuzztape/budget"
	"github.com/tmc/go-iroh/internal/fuzztape/sched"
	"github.com/tmc/go-iroh/internal/fuzztape/stats"
	"github.com/tmc/go-iroh/netaddr"
)

// The scheduler controls fake provider responses, not Downloader's internal
// goroutines. Workers enqueue requests and await replies; only responders
// registered with Scheduler.Go call Yield. Bubble supplies quiescence and the
// ledger checks public work and fake transport lifetimes after cleanup.
type downloaderMachine struct {
	mu         sync.Mutex
	scheduler  *sched.Scheduler
	ledger     budget.Ledger
	downloader *Downloader
	jobs       []*downloaderJob
	opens      []*downloaderOpen
	streams    []*accountedBlobStream
	data       []byte
	encoded    []byte
	shared     bool
}

type downloaderJobKey struct{}

type downloaderJob struct {
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	err    error
	tag    *TempTag
}

type downloaderOpen struct {
	jobID int
	ctx   context.Context
	conn  *accountedBlobConn
	reply chan downloaderOpenReply
}

type downloaderOpenReply struct {
	stream BidiStream
	err    error
}

func downloaderMachineSpec(shared bool) fuzztape.Machine[*downloaderMachine] {
	return fuzztape.Machine[*downloaderMachine]{
		Bubble: true, MaxOps: 24,
		Init: func(t *fuzztape.T) *downloaderMachine {
			m := &downloaderMachine{data: []byte("scheduled downloader content"), shared: shared}
			_, encoded, err := EncodeBlob(m.data)
			if err != nil {
				t.Fatalf("encode fixture: %v", err)
			}
			m.encoded = encoded
			m.ledger.Balanced(t) // registered first, checked after every cleanup
			m.scheduler = sched.New(t)
			m.downloader = NewDownloader(&downloadStore{}, BlobConnectorFunc(func(ctx context.Context, _ netaddr.EndpointAddr, _ string) (BlobConn, error) {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				m.ledger.Acquire("connection")
				return &accountedBlobConn{machine: m}, nil
			}), DownloaderOptions{StallTimeout: -1})
			t.Cleanup(func() {
				for _, job := range m.jobs {
					job.cancel()
				}
				m.scheduler.Settle()
				synctest.Wait()
				for _, job := range m.jobs {
					<-job.done
					if job.tag != nil {
						_ = job.tag.Close()
					}
				}
				if outstanding := m.ledger.Outstanding("stream"); outstanding != 0 {
					t.Errorf("downloads finished with %d streams still open before closing connections", outstanding)
				}
				if err := m.downloader.Close(); err != nil {
					t.Errorf("close downloader: %v", err)
				}
				synctest.Wait()
				if m.ledger.Peak("work") > 3 || m.ledger.Peak("connection") > 6 || m.ledger.Peak("stream") > 3 {
					t.Errorf("resource peaks exceeded fixture's three-job/two-provider bounds")
				}
			})
			return m
		},
		Ops: []fuzztape.Op[*downloaderMachine]{
			{Name: "start", When: func(m *downloaderMachine) bool {
				limit := 1
				if m.shared {
					limit = 2
				}
				return len(m.jobs) < 3 && len(m.active()) < limit
			}, Apply: func(t *fuzztape.T, m *downloaderMachine) {
				ctx, cancel := context.WithCancel(context.WithValue(context.Background(), downloaderJobKey{}, len(m.jobs)))
				job := &downloaderJob{ctx: ctx, cancel: cancel, done: make(chan struct{})}
				m.jobs = append(m.jobs, job)
				m.ledger.Acquire("work")
				go func() {
					job.tag, job.err = m.downloader.Download(ctx, NewHash(m.data), []netaddr.EndpointAddr{testEndpointAddr(81), testEndpointAddr(82)})
					m.ledger.Release("work")
					close(job.done)
				}()
				synctest.Wait()
			}},
			{Name: "open", When: func(m *downloaderMachine) bool { return m.openCount() != 0 }, Apply: func(t *fuzztape.T, m *downloaderMachine) { m.scheduleOpen(t, false) }},
			{Name: "failOpen", When: func(m *downloaderMachine) bool { return m.openCount() != 0 }, Apply: func(t *fuzztape.T, m *downloaderMachine) { m.scheduleOpen(t, true) }},
			{Name: "cancel", When: func(m *downloaderMachine) bool { return len(m.active()) != 0 }, Apply: func(t *fuzztape.T, m *downloaderMachine) {
				jobs := m.active()
				jobs[t.IntN(len(jobs))].cancel()
				synctest.Wait()
			}},
			sched.StepOp("step", func(m *downloaderMachine) *sched.Scheduler { return m.scheduler }),
			{Name: "respond", When: func(m *downloaderMachine) bool { return len(m.waitingResponses()) != 0 }, Apply: func(t *fuzztape.T, m *downloaderMachine) {
				streams := m.waitingResponses()
				stream := streams[t.IntN(len(streams))]
				stream.mu.Lock()
				stream.scheduled = true
				stream.mu.Unlock()
				m.scheduler.Go("respond", func() { m.scheduler.Yield(); close(stream.response) })
			}},
		},
		Check: func(t *fuzztape.T, m *downloaderMachine) {
			if shared {
				m.mu.Lock()
				streams := slices.Clone(m.streams)
				m.mu.Unlock()
				for _, stream := range streams {
					job := m.jobs[stream.jobID]
					select {
					case <-job.done:
						continue
					default:
					}
					select {
					case <-stream.aborted:
						if job.ctx.Err() == nil {
							t.Fatalf("uncanceled stream was aborted after schedule [%s]", m.scheduler)
						}
					default:
					}
				}
			}
			for _, job := range m.jobs {
				select {
				case <-job.done:
					if job.err == nil && (job.tag == nil || job.tag.Hash() != NewHash(m.data)) {
						t.Fatalf("successful download returned wrong blob")
					}
					if shared && job.ctx.Err() == nil && job.err != nil && !errors.Is(job.err, errScheduledOpen) {
						t.Fatalf("unrelated download failed after schedule [%s]: %v", m.scheduler, job.err)
					}
				default:
				}
			}
		},
	}
}

var errScheduledOpen = errors.New("scheduled provider failure")

func (m *downloaderMachine) active() []*downloaderJob {
	var out []*downloaderJob
	for _, job := range m.jobs {
		select {
		case <-job.done:
		default:
			if job.ctx.Err() == nil {
				out = append(out, job)
			}
		}
	}
	return out
}

func (m *downloaderMachine) openCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.opens)
}

func (m *downloaderMachine) scheduleOpen(t *fuzztape.T, fail bool) {
	m.mu.Lock()
	i := t.IntN(len(m.opens))
	req := m.opens[i]
	m.opens = append(m.opens[:i], m.opens[i+1:]...)
	m.mu.Unlock()
	m.scheduler.Go("open", func() {
		m.scheduler.Yield()
		reply := downloaderOpenReply{err: req.ctx.Err()}
		if reply.err == nil {
			if fail {
				reply.err = errScheduledOpen
			} else {
				reply.stream, reply.err = req.conn.newStream(req.jobID)
			}
		}
		req.reply <- reply
	})
}

func (m *downloaderMachine) waitingResponses() []*accountedBlobStream {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*accountedBlobStream
	for _, stream := range m.streams {
		stream.mu.Lock()
		if !stream.scheduled && !stream.readDone {
			out = append(out, stream)
		}
		stream.mu.Unlock()
	}
	return out
}

type accountedBlobConn struct {
	mu      sync.Mutex
	machine *downloaderMachine
	closed  bool
	streams []*accountedBlobStream
}

func (c *accountedBlobConn) OpenStreamSync(ctx context.Context) (BidiStream, error) {
	req := &downloaderOpen{ctx: ctx, conn: c, reply: make(chan downloaderOpenReply, 1), jobID: ctx.Value(downloaderJobKey{}).(int)}
	c.machine.mu.Lock()
	c.machine.opens = append(c.machine.opens, req)
	slices.SortFunc(c.machine.opens, func(a, b *downloaderOpen) int { return cmp.Compare(a.jobID, b.jobID) })
	c.machine.mu.Unlock()
	select {
	case reply := <-req.reply:
		return reply.stream, reply.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *accountedBlobConn) newStream(jobID int) (BidiStream, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, io.ErrClosedPipe
	}
	s := &accountedBlobStream{reader: bytes.NewReader(c.machine.encoded), response: make(chan struct{}), aborted: make(chan struct{}), ledger: &c.machine.ledger, jobID: jobID}
	s.ledger.Acquire("stream")
	c.streams = append(c.streams, s)
	c.machine.mu.Lock()
	c.machine.streams = append(c.machine.streams, s)
	c.machine.mu.Unlock()
	return s, nil
}

func (c *accountedBlobConn) CloseWithError(uint64, string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	for _, stream := range c.streams {
		stream.CancelRead(0)
		_ = stream.Close()
	}
	c.machine.ledger.Release("connection")
	return nil
}

type accountedBlobStream struct {
	jobID                                    int
	mu                                       sync.Mutex
	reader                                   *bytes.Reader
	response                                 chan struct{}
	aborted                                  chan struct{}
	ledger                                   *budget.Ledger
	scheduled, readDone, writeDone, released bool
}

func (s *accountedBlobStream) Read(p []byte) (int, error) {
	select {
	case <-s.aborted:
		return 0, io.ErrClosedPipe
	case <-s.response:
	}
	select {
	case <-s.aborted:
		return 0, io.ErrClosedPipe
	default:
	}
	n, err := s.reader.Read(p)
	if err != nil {
		s.mu.Lock()
		s.readDone = true
		s.release()
		s.mu.Unlock()
	}
	return n, err
}
func (s *accountedBlobStream) Write(p []byte) (int, error) { return len(p), nil }
func (s *accountedBlobStream) Close() error                { return s.CloseWrite() }
func (s *accountedBlobStream) CloseWrite() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writeDone = true
	s.release()
	return nil
}
func (s *accountedBlobStream) CancelRead(uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.readDone {
		s.readDone = true
		close(s.aborted)
	}
	s.release()
}
func (s *accountedBlobStream) release() {
	if s.readDone && s.writeDone && !s.released {
		s.released = true
		s.ledger.Release("stream")
	}
}

var scheduledDownloaderSeeds = []struct {
	name    string
	data    []byte
	success bool
}{
	{"success", []byte{0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0}, true},
	{"failover", []byte{0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0}, true},
	{"cancel", []byte{0, 2, 0}, false},
}

func TestScheduledDownloaderMachine(t *testing.T) {
	m := downloaderMachineSpec(false)
	ops, report := stats.Wrap(m.Ops)
	m.Ops = ops
	for _, seed := range scheduledDownloaderSeeds {
		t.Run(seed.name, func(t *testing.T) {
			seeded := m
			init := seeded.Init
			seeded.Init = func(ft *fuzztape.T) *downloaderMachine {
				state := init(ft)
				ft.Cleanup(func() {
					if len(state.jobs) != 1 {
						ft.Errorf("seed started %d jobs, want one", len(state.jobs))
						return
					}
					job := state.jobs[0]
					select {
					case <-job.done:
					default:
						ft.Errorf("seed did not finish download before cleanup")
						return
					}
					if seed.success && job.err != nil {
						ft.Errorf("seed did not produce successful download: %v", job.err)
					}
					if !seed.success && !errors.Is(job.err, context.Canceled) {
						ft.Errorf("canceled seed returned %v", job.err)
					}
				})
				return state
			}
			seeded.Replay(t, seed.data)
		})
	}
	m.Run(t, 60)
	report.Log(t)
	if missing := report.Missing(); len(missing) != 0 {
		t.Fatalf("operations never applied: %v", missing)
	}
}

func FuzzScheduledDownloaderMachine(f *testing.F) {
	for _, seed := range scheduledDownloaderSeeds {
		f.Add(seed.data)
	}
	downloaderMachineSpec(false).Fuzz(f)
}
