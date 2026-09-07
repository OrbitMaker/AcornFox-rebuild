package main

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/open-card/open-card/internal/acornfoxcandidate"
	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/domain"
)

const (
	acornFoxFixCandidateQueueCapacity  = 8
	acornFoxFixCandidateExecutionLimit = 20 * time.Minute
	acornFoxFixCandidateLeaderProbe    = 250 * time.Millisecond
	acornFoxFixCandidateLeaderSettle   = 2 * acornFoxFixCandidateLeaderProbe
)

type acornFoxFixCandidateJob struct {
	accepted application.AcornFoxFixCandidate
	request  application.AcornFoxFixCandidateCreateRequest
	digest   string
}

type acornFoxFixCandidateAsyncCommand interface {
	Replay(context.Context, application.AcornFoxFixCandidateCreateRequest) (*application.AcornFoxFixCandidate, error)
	Accept(context.Context, application.AcornFoxFixCandidateCreateRequest) (application.AcornFoxFixCandidate, bool, string, error)
	Execute(context.Context, application.AcornFoxFixCandidate, application.AcornFoxFixCandidateCreateRequest, string) (application.AcornFoxFixCandidate, error)
	ReadSource(context.Context, domain.ID, domain.ID, []string) (acornfoxcandidate.ReadResult, error)
	ReadSourceForAI(context.Context, domain.ID, domain.ID, []string) (acornfoxcandidate.ReadResult, error)
	MatchSource(context.Context, domain.ID, domain.ID, domain.ID, domain.ID) (application.AcornFoxFixCandidate, error)
	Publish(context.Context, domain.ID, domain.ID, domain.ID, string) (application.AcornFoxDeliveryResult, error)
}

type acornFoxFixCandidateCoordinator struct {
	service acornFoxFixCandidateAsyncCommand
	ctx     context.Context
	cancel  context.CancelFunc
	queue   chan acornFoxFixCandidateJob
	slots   chan struct{}
	mu      sync.Mutex
	closing bool
	workers sync.WaitGroup
}

func newAcornFoxFixCandidateCoordinator(lifecycle context.Context, service acornFoxFixCandidateAsyncCommand) (*acornFoxFixCandidateCoordinator, error) {
	if lifecycle == nil || service == nil {
		return nil, errors.New("fix candidate coordinator dependencies are unavailable")
	}
	ctx, cancel := context.WithCancel(lifecycle)
	coordinator := &acornFoxFixCandidateCoordinator{service: service, ctx: ctx, cancel: cancel, queue: make(chan acornFoxFixCandidateJob, acornFoxFixCandidateQueueCapacity), slots: make(chan struct{}, acornFoxFixCandidateQueueCapacity)}
	coordinator.workers.Add(1)
	go coordinator.run()
	return coordinator, nil
}

// Create only reserves durable work and queues it. Queue capacity is reserved
// before the preparing row is inserted, so an accepted row is never orphaned
// merely because the local queue is full.
func (c *acornFoxFixCandidateCoordinator) Create(ctx context.Context, request application.AcornFoxFixCandidateCreateRequest) (application.AcornFoxFixCandidate, error) {
	if c == nil || c.service == nil {
		return application.AcornFoxFixCandidate{}, domain.NewError(domain.ErrUnavailable, "fix candidate is unavailable")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closing || c.ctx.Err() != nil {
		return application.AcornFoxFixCandidate{}, domain.NewError(domain.ErrUnavailable, "fix candidate is stopping")
	}
	if replay, err := c.service.Replay(ctx, request); err != nil {
		return application.AcornFoxFixCandidate{}, err
	} else if replay != nil {
		return *replay, nil
	}
	select {
	case c.slots <- struct{}{}:
	default:
		return application.AcornFoxFixCandidate{}, domain.NewError(domain.ErrUnavailable, "fix candidate queue is full")
	}
	accepted, inserted, digest, err := c.service.Accept(ctx, request)
	if err != nil || !inserted {
		<-c.slots
		return accepted, err
	}
	c.queue <- acornFoxFixCandidateJob{accepted: accepted, request: request, digest: digest}
	return accepted, nil
}

func (c *acornFoxFixCandidateCoordinator) run() {
	defer c.workers.Done()
	for {
		select {
		case job := <-c.queue:
			c.execute(job)
		case <-c.ctx.Done():
			for {
				select {
				case job := <-c.queue:
					c.execute(job)
				default:
					return
				}
			}
		}
	}
}

func (c *acornFoxFixCandidateCoordinator) execute(job acornFoxFixCandidateJob) {
	defer func() { <-c.slots }()
	ctx, cancel := context.WithTimeout(c.ctx, acornFoxFixCandidateExecutionLimit)
	defer cancel()
	_, _ = c.service.Execute(ctx, job.accepted, job.request, job.digest)
}

func (c *acornFoxFixCandidateCoordinator) Close(ctx context.Context) error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	if !c.closing {
		c.closing = true
		c.cancel()
	}
	c.mu.Unlock()
	done := make(chan struct{})
	go func() {
		c.workers.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *acornFoxFixCandidateCoordinator) ReadSource(ctx context.Context, applicationID, sourceRevisionID domain.ID, paths []string) (acornfoxcandidate.ReadResult, error) {
	return c.service.ReadSource(ctx, applicationID, sourceRevisionID, paths)
}

func (c *acornFoxFixCandidateCoordinator) ReadSourceForAI(ctx context.Context, applicationID, sourceRevisionID domain.ID, paths []string) (acornfoxcandidate.ReadResult, error) {
	return c.service.ReadSourceForAI(ctx, applicationID, sourceRevisionID, paths)
}

func (c *acornFoxFixCandidateCoordinator) MatchSource(ctx context.Context, applicationID, candidateID, sourceRevisionID, ownerAdminID domain.ID) (application.AcornFoxFixCandidate, error) {
	return c.service.MatchSource(ctx, applicationID, candidateID, sourceRevisionID, ownerAdminID)
}

func (c *acornFoxFixCandidateCoordinator) Publish(ctx context.Context, applicationID, candidateID, ownerAdminID domain.ID, idempotencyKey string) (application.AcornFoxDeliveryResult, error) {
	return c.service.Publish(ctx, applicationID, candidateID, ownerAdminID, idempotencyKey)
}
