package loader

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf/perf"
)

// EventCallback is called for each received event.
type EventCallback func(event Event)

// EventReader reads events from the BPF perf buffer.
type EventReader struct {
	loader      *Loader
	eventChan   chan Event
	callback    EventCallback
	bufferSize  int
	running     atomic.Bool
	wg          sync.WaitGroup
	lostEvents  atomic.Uint64
	totalEvents atomic.Uint64
	parseErrors atomic.Uint64
}

// ReaderConfig contains configuration for the event reader.
type ReaderConfig struct {
	ChannelSize int           // Size of event channel (default: 1000)
	Callback    EventCallback // Optional callback for each event
}

// DefaultReaderConfig returns default reader configuration.
func DefaultReaderConfig() *ReaderConfig {
	return &ReaderConfig{
		ChannelSize: 1000,
	}
}

// NewEventReader creates a new event reader for the given loader.
func NewEventReader(loader *Loader, cfg *ReaderConfig) *EventReader {
	if cfg == nil {
		cfg = DefaultReaderConfig()
	}

	return &EventReader{
		loader:     loader,
		eventChan:  make(chan Event, cfg.ChannelSize),
		callback:   cfg.Callback,
		bufferSize: cfg.ChannelSize,
	}
}

// Start begins reading events from the perf buffer.
// It will run until the context is cancelled or Close is called.
func (r *EventReader) Start(ctx context.Context) error {
	if r.running.Load() {
		return fmt.Errorf("reader already running")
	}
	r.running.Store(true)

	r.wg.Add(1)
	go r.readLoop(ctx)

	return nil
}

// readLoop continuously reads events from the perf buffer.
func (r *EventReader) readLoop(ctx context.Context) {
	defer r.wg.Done()
	defer r.running.Store(false)
	defer close(r.eventChan)

	perfReader := r.loader.PerfReader()
	if perfReader == nil {
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := perfReader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			// Log error but continue
			continue
		}

		// Handle lost events
		if record.LostSamples > 0 {
			r.lostEvents.Add(record.LostSamples)
			continue
		}

		// Parse event
		event, err := ParseEvent(record.RawSample)
		if err != nil {
			r.parseErrors.Add(1)
			continue
		}

		r.totalEvents.Add(1)

		// Call callback if set
		if r.callback != nil {
			r.callback(event)
		}

		// Send to channel (non-blocking)
		select {
		case r.eventChan <- event:
		default:
			// Channel full, drop event
			r.lostEvents.Add(1)
		}
	}
}

// Events returns the channel for receiving events.
func (r *EventReader) Events() <-chan Event {
	return r.eventChan
}

// Stop stops the event reader.
func (r *EventReader) Stop() {
	if !r.running.Load() {
		return
	}
	// Close perf reader to unblock Read()
	if r.loader.PerfReader() != nil {
		r.loader.PerfReader().Close()
	}
	r.wg.Wait()
}

// Stats returns reader statistics.
func (r *EventReader) Stats() ReaderStats {
	return ReaderStats{
		TotalEvents: r.totalEvents.Load(),
		LostEvents:  r.lostEvents.Load(),
		ParseErrors: r.parseErrors.Load(),
	}
}

// ReaderStats contains reader statistics.
type ReaderStats struct {
	TotalEvents uint64
	LostEvents  uint64
	ParseErrors uint64
}

// String returns a string representation of the stats.
func (s ReaderStats) String() string {
	return fmt.Sprintf("total=%d lost=%d errors=%d", s.TotalEvents, s.LostEvents, s.ParseErrors)
}

// EventProcessor processes events from the reader and converts them.
type EventProcessor struct {
	reader    *EventReader
	converter EventConverterFunc
	output    chan []byte
	running   atomic.Bool
	wg        sync.WaitGroup
}

// EventConverterFunc converts an event to bytes.
type EventConverterFunc func(event Event) ([]byte, error)

// NewEventProcessor creates a new event processor.
func NewEventProcessor(reader *EventReader, converter EventConverterFunc, outputSize int) *EventProcessor {
	return &EventProcessor{
		reader:    reader,
		converter: converter,
		output:    make(chan []byte, outputSize),
	}
}

// Start begins processing events.
func (p *EventProcessor) Start(ctx context.Context) error {
	if p.running.Load() {
		return fmt.Errorf("processor already running")
	}
	p.running.Store(true)

	p.wg.Add(1)
	go p.processLoop(ctx)

	return nil
}

// processLoop reads events and converts them.
func (p *EventProcessor) processLoop(ctx context.Context) {
	defer p.wg.Done()
	defer p.running.Store(false)
	defer close(p.output)

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-p.reader.Events():
			if !ok {
				return
			}

			data, err := p.converter(event)
			if err != nil || data == nil {
				continue
			}

			select {
			case p.output <- data:
			default:
				// Output full, drop
			}
		}
	}
}

// Output returns the channel for receiving converted events.
func (p *EventProcessor) Output() <-chan []byte {
	return p.output
}

// Stop stops the processor.
func (p *EventProcessor) Stop() {
	p.reader.Stop()
	p.wg.Wait()
}
