// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package agent implements the trace-agent.
package agent

import (
	"context"
	"runtime"
	"strconv"
	"sync"
	"time"

	compression "github.com/DataDog/datadog-agent/comp/trace/compression/def"
	"github.com/DataDog/datadog-agent/pkg/obfuscate"
	pb "github.com/DataDog/datadog-agent/pkg/proto/pbgo/trace"
	"github.com/DataDog/datadog-agent/pkg/trace/api"
	"github.com/DataDog/datadog-agent/pkg/trace/config"
	"github.com/DataDog/datadog-agent/pkg/trace/event"
	"github.com/DataDog/datadog-agent/pkg/trace/filters"
	"github.com/DataDog/datadog-agent/pkg/trace/info"
	"github.com/DataDog/datadog-agent/pkg/trace/log"
	"github.com/DataDog/datadog-agent/pkg/trace/remoteconfighandler"
	"github.com/DataDog/datadog-agent/pkg/trace/sampler"
	"github.com/DataDog/datadog-agent/pkg/trace/stats"
	"github.com/DataDog/datadog-agent/pkg/trace/telemetry"
	"github.com/DataDog/datadog-agent/pkg/trace/timing"
	"github.com/DataDog/datadog-agent/pkg/trace/traceutil"
	"github.com/DataDog/datadog-agent/pkg/trace/version"
	"github.com/DataDog/datadog-agent/pkg/trace/writer"

	"github.com/DataDog/datadog-go/v5/statsd"
)

const (
	// tagHostname specifies the hostname of the tracer.
	// DEPRECATED: Tracer hostname is now specified as a TracerPayload field.
	tagHostname = "_dd.hostname"

	// tagInstallID, tagInstallType, and tagInstallTime are included in the first trace sent by the agent,
	// and used to track successful onboarding onto APM.
	tagInstallID   = "_dd.install.id"
	tagInstallType = "_dd.install.type"
	tagInstallTime = "_dd.install.time"

	// manualSampling is the value for _dd.p.dm when user sets sampling priority directly in code.
	manualSampling = "-4"

	// probabilitySampling is the value for _dd.p.dm when the agent is configured to use the ProbabilitySampler.
	probabilitySampling = "-9"

	// tagDecisionMaker specifies the sampling decision maker
	tagDecisionMaker = "_dd.p.dm"
)

// TraceWriter provides a way to write trace chunks
type TraceWriter interface {
	// Stop stops the TraceWriter and attempts to flush whatever is left in the senders buffers.
	Stop()

	// WriteChunks to be written
	WriteChunks(pkg *writer.SampledChunks)

	// FlushSync blocks and sends pending payloads when syncMode is true
	FlushSync() error
}

// Concentrator accepts stats input, 'concentrating' them together into buckets before flushing them
type Concentrator interface {
	// Start starts the Concentrator
	Start()
	// Stop stops the Concentrator and attempts to flush whatever is left in the buffers
	Stop()
	// Add a stats Input to be concentrated and flushed
	Add(t stats.Input)
}

// Agent struct holds all the sub-routines structs and make the data flow between them
type Agent struct {
	Receiver              *api.HTTPReceiver
	OTLPReceiver          *api.OTLPReceiver
	Concentrator          Concentrator
	ClientStatsAggregator *stats.ClientStatsAggregator
	Blacklister           *filters.Blacklister
	Replacer              *filters.Replacer
	PrioritySampler       *sampler.PrioritySampler
	ErrorsSampler         *sampler.ErrorsSampler
	RareSampler           *sampler.RareSampler
	NoPrioritySampler     *sampler.NoPrioritySampler
	ProbabilisticSampler  *sampler.ProbabilisticSampler
	EventProcessor        *event.Processor
	TraceWriter           TraceWriter
	StatsWriter           *writer.DatadogStatsWriter
	RemoteConfigHandler   *remoteconfighandler.RemoteConfigHandler
	TelemetryCollector    telemetry.TelemetryCollector
	DebugServer           *api.DebugServer
	Statsd                statsd.ClientInterface
	Timing                timing.Reporter

	// obfuscator is used to obfuscate sensitive data from various span
	// tags based on their type.
	obfuscator *obfuscate.Obfuscator

	// DiscardSpan will be called on all spans, if non-nil. If it returns true, the span will be deleted before processing.
	DiscardSpan func(*pb.Span) bool

	// SpanModifier will be called on all non-nil spans of received trace chunks.
	// Note that any modification of the trace chunk could be overwritten by
	// subsequent SpanModifier calls.
	SpanModifier SpanModifier

	// In takes incoming payloads to be processed by the agent.
	In chan *api.Payload

	// config
	conf *config.AgentConfig

	// Used to synchronize on a clean exit
	ctx context.Context

	firstSpanMap sync.Map
}

// SpanModifier is an interface that allows to modify spans while they are
// processed by the agent.
type SpanModifier interface {
	ModifySpan(*pb.TraceChunk, *pb.Span)
}

// NewAgent returns a new Agent object, ready to be started. It takes a context
// which may be cancelled in order to gracefully stop the agent.
func NewAgent(ctx context.Context, conf *config.AgentConfig, telemetryCollector telemetry.TelemetryCollector, statsd statsd.ClientInterface, comp compression.Component) *Agent {
	dynConf := sampler.NewDynamicConfig()
	log.Infof("Starting Agent with processor trace buffer of size %d", conf.TraceBuffer)
	in := make(chan *api.Payload, conf.TraceBuffer)
	oconf := conf.Obfuscation.Export(conf)
	if oconf.Statsd == nil {
		oconf.Statsd = statsd
	}
	timing := timing.New(statsd)
	statsWriter := writer.NewStatsWriter(conf, telemetryCollector, statsd, timing)
	agnt := &Agent{
		Concentrator:          stats.NewConcentrator(conf, statsWriter, time.Now(), statsd),
		ClientStatsAggregator: stats.NewClientStatsAggregator(conf, statsWriter, statsd),
		Blacklister:           filters.NewBlacklister(conf.Ignore["resource"]),
		Replacer:              filters.NewReplacer(conf.ReplaceTags),
		PrioritySampler:       sampler.NewPrioritySampler(conf, dynConf, statsd),
		ErrorsSampler:         sampler.NewErrorsSampler(conf, statsd),
		RareSampler:           sampler.NewRareSampler(conf, statsd),
		NoPrioritySampler:     sampler.NewNoPrioritySampler(conf, statsd),
		ProbabilisticSampler:  sampler.NewProbabilisticSampler(conf, statsd),
		EventProcessor:        newEventProcessor(conf, statsd),
		StatsWriter:           statsWriter,
		obfuscator:            obfuscate.NewObfuscator(oconf),
		In:                    in,
		conf:                  conf,
		ctx:                   ctx,
		DebugServer:           api.NewDebugServer(conf),
		Statsd:                statsd,
		Timing:                timing,
	}
	agnt.Receiver = api.NewHTTPReceiver(conf, dynConf, in, agnt, telemetryCollector, statsd, timing)
	agnt.OTLPReceiver = api.NewOTLPReceiver(in, conf, statsd, timing)
	agnt.RemoteConfigHandler = remoteconfighandler.New(conf, agnt.PrioritySampler, agnt.RareSampler, agnt.ErrorsSampler)
	agnt.TraceWriter = writer.NewTraceWriter(conf, agnt.PrioritySampler, agnt.ErrorsSampler, agnt.RareSampler, telemetryCollector, statsd, timing, comp)
	return agnt
}

// Run starts routers routines and individual pieces then stop them when the exit order is received.
func (a *Agent) Run() {
	a.Timing.Start()
	defer a.Timing.Stop()
	for _, starter := range []interface{ Start() }{
		a.Receiver,
		a.Concentrator,
		a.ClientStatsAggregator,
		a.PrioritySampler,
		a.ErrorsSampler,
		a.NoPrioritySampler,
		a.ProbabilisticSampler,
		a.EventProcessor,
		a.OTLPReceiver,
		a.RemoteConfigHandler,
		a.DebugServer,
	} {
		starter.Start()
	}

	go a.StatsWriter.Run()

	// Having GOMAXPROCS processor threads is
	// enough to keep the agent busy.
	// Having more processor threads would not speed
	// up processing, but just expand memory.
	workers := runtime.GOMAXPROCS(0)
	if workers < 1 {
		workers = 1
	}

	log.Infof("Processing Pipeline configured with %d workers", workers)
	for i := 0; i < workers; i++ {
		go a.work()
	}

	a.loop()
}

// FlushSync flushes traces synchronously. This method only works when the agent is configured in synchronous flushing
// mode via the apm_config.sync_flush option.
func (a *Agent) FlushSync() {
	if !a.conf.SynchronousFlushing {
		log.Critical("(*Agent).FlushSync called without apm_conf.sync_flushing enabled. No data was sent to Datadog.")
		return
	}

	if err := a.StatsWriter.FlushSync(); err != nil {
		log.Errorf("Error flushing stats: %s", err.Error())
		return
	}
	if err := a.TraceWriter.FlushSync(); err != nil {
		log.Errorf("Error flushing traces: %s", err.Error())
		return
	}
}

func (a *Agent) work() {
	for {
		p, ok := <-a.In
		if !ok {
			return
		}
		a.Process(p)
	}

}

func (a *Agent) loop() {
	<-a.ctx.Done()
	log.Info("Exiting...")

	a.OTLPReceiver.Stop() // Stop OTLPReceiver before Receiver to avoid sending to closed channel
	if err := a.Receiver.Stop(); err != nil {
		log.Error(err)
	}
	for _, stopper := range []interface{ Stop() }{
		a.Concentrator,
		a.ClientStatsAggregator,
		a.TraceWriter,
		a.StatsWriter,
		a.PrioritySampler,
		a.ErrorsSampler,
		a.NoPrioritySampler,
		a.ProbabilisticSampler,
		a.RareSampler,
		a.EventProcessor,
		a.obfuscator,
		a.DebugServer,
	} {
		stopper.Stop()
	}
}

// setRootSpanTags sets up any necessary tags on the root span.
func (a *Agent) setRootSpanTags(root *pb.Span) {
	clientSampleRate := sampler.GetGlobalRate(root)
	sampler.SetClientRate(root, clientSampleRate)
}

// setFirstTraceTags sets additional tags on the first trace for each service processed by the agent,
// so that we can see that the service has successfully onboarded onto APM.
func (a *Agent) setFirstTraceTags(root *pb.Span) {
	if a.conf == nil || a.conf.InstallSignature.InstallID == "" || root == nil {
		return
	}
	if _, alreadySeenService := a.firstSpanMap.LoadOrStore(root.Service, true); !alreadySeenService {
		// The install time and type can also be set on the trace by the tracer,
		// in which case we do not want the agent to overwrite them.
		if _, ok := traceutil.GetMeta(root, tagInstallID); !ok {
			traceutil.SetMeta(root, tagInstallID, a.conf.InstallSignature.InstallID)
		}
		if _, ok := traceutil.GetMeta(root, tagInstallType); !ok {
			traceutil.SetMeta(root, tagInstallType, a.conf.InstallSignature.InstallType)
		}
		if _, ok := traceutil.GetMeta(root, tagInstallTime); !ok {
			traceutil.SetMeta(root, tagInstallTime, strconv.FormatInt(a.conf.InstallSignature.InstallTime, 10))
		}
	}
}

// Process is the default work unit that receives a trace, transforms it and
// passes it downstream.
func (a *Agent) Process(p *api.Payload) {
	if len(p.Chunks()) == 0 {
		log.Debugf("Skipping received empty payload")
		return
	}
	now := time.Now()
	defer a.Timing.Since("datadog.trace_agent.internal.process_payload_ms", now)
	ts := p.Source
	sampledChunks := new(writer.SampledChunks)
	statsInput := stats.NewStatsInput(len(p.TracerPayload.Chunks), p.TracerPayload.ContainerID, p.ClientComputedStats, a.conf)

	p.TracerPayload.Env = traceutil.NormalizeTag(p.TracerPayload.Env)

	a.discardSpans(p)

	for i := 0; i < len(p.Chunks()); {
		chunk := p.Chunk(i)
		if len(chunk.Spans) == 0 {
			log.Debugf("Skipping received empty trace")
			p.RemoveChunk(i)
			continue
		}

		tracen := int64(len(chunk.Spans))
		ts.SpansReceived.Add(tracen)
		err := a.normalizeTrace(p.Source, chunk.Spans)
		if err != nil {
			log.Debugf("Dropping invalid trace: %s", err)
			ts.SpansDropped.Add(tracen)
			p.RemoveChunk(i)
			continue
		}

		// Root span is used to carry some trace-level metadata, such as sampling rate and priority.
		root := traceutil.GetRoot(chunk.Spans)
		setChunkAttributes(chunk, root)
		if !a.Blacklister.Allows(root) {
			log.Debugf("Trace rejected by ignore resources rules. root: %v", root)
			ts.TracesFiltered.Inc()
			ts.SpansFiltered.Add(tracen)
			p.RemoveChunk(i)
			continue
		}

		if filteredByTags(root, a.conf.RequireTags, a.conf.RejectTags, a.conf.RequireTagsRegex, a.conf.RejectTagsRegex) {
			log.Debugf("Trace rejected as it fails to meet tag requirements. root: %v", root)
			ts.TracesFiltered.Inc()
			ts.SpansFiltered.Add(tracen)
			p.RemoveChunk(i)
			continue
		}

		// Extra sanitization steps of the trace.
		for _, span := range chunk.Spans {
			for k, v := range a.conf.GlobalTags {
				if k == tagOrigin {
					chunk.Origin = v
				} else {
					traceutil.SetMeta(span, k, v)
				}
			}
			if a.SpanModifier != nil {
				a.SpanModifier.ModifySpan(chunk, span)
			}
			a.obfuscateSpan(span)
			a.Truncate(span)
			if p.ClientComputedTopLevel {
				traceutil.UpdateTracerTopLevel(span)
			}
		}
		a.Replacer.Replace(chunk.Spans)

		a.setRootSpanTags(root)
		if !p.ClientComputedTopLevel {
			// Figure out the top-level spans now as it involves modifying the Metrics map
			// which is not thread-safe while samplers and concentrator might modify it too.
			traceutil.ComputeTopLevel(chunk.Spans)
		}

		a.setPayloadAttributes(p, root, chunk)

		pt := processedTrace(p, chunk, root, p.TracerPayload.ContainerID, a.conf)
		if !p.ClientComputedStats {
			statsInput.Traces = append(statsInput.Traces, *pt.Clone())
		}

		keep, numEvents := a.sample(now, ts, pt)
		if !keep && len(pt.TraceChunk.Spans) == 0 {
			// The entire trace was dropped and no spans were kept.
			p.RemoveChunk(i)
			continue
		}
		p.ReplaceChunk(i, pt.TraceChunk)

		if !pt.TraceChunk.DroppedTrace {
			// Now that we know this trace has been sampled,
			// if this is the first trace we have processed since restart,
			// set a special set of tags on its root span to track that this
			// customer has successfully onboarded onto APM.
			a.setFirstTraceTags(root)
			sampledChunks.SpanCount += int64(len(pt.TraceChunk.Spans))
		}
		sampledChunks.EventCount += int64(numEvents)
		sampledChunks.Size += pt.TraceChunk.Msgsize()
		i++

		if sampledChunks.Size > writer.MaxPayloadSize {
			// payload size is getting big; split and flush what we have so far
			sampledChunks.TracerPayload = p.TracerPayload.Cut(i)
			i = 0
			sampledChunks.TracerPayload.Chunks = newChunksArray(sampledChunks.TracerPayload.Chunks)
			a.TraceWriter.WriteChunks(sampledChunks)
			sampledChunks = new(writer.SampledChunks)
		}
	}
	sampledChunks.TracerPayload = p.TracerPayload
	sampledChunks.TracerPayload.Chunks = newChunksArray(p.TracerPayload.Chunks)
	if sampledChunks.Size > 0 {
		a.TraceWriter.WriteChunks(sampledChunks)
	}
	if len(statsInput.Traces) > 0 {
		a.Concentrator.Add(statsInput)
	}
}

func (a *Agent) setPayloadAttributes(p *api.Payload, root *pb.Span, chunk *pb.TraceChunk) {
	if p.TracerPayload.Hostname == "" {
		// Older tracers set tracer hostname in the root span.
		p.TracerPayload.Hostname = root.Meta[tagHostname]
	}
	if p.TracerPayload.Env == "" {
		p.TracerPayload.Env = traceutil.GetEnv(root, chunk)
	}
	if p.TracerPayload.AppVersion == "" {
		p.TracerPayload.AppVersion = version.GetAppVersionFromTrace(root, chunk)
	}
}

// processedTrace creates a ProcessedTrace based on the provided chunk, root, containerID, and agent config.
func processedTrace(p *api.Payload, chunk *pb.TraceChunk, root *pb.Span, containerID string, conf *config.AgentConfig) *traceutil.ProcessedTrace {
	pt := &traceutil.ProcessedTrace{
		TraceChunk:             chunk,
		Root:                   root,
		AppVersion:             p.TracerPayload.AppVersion,
		TracerEnv:              p.TracerPayload.Env,
		TracerHostname:         p.TracerPayload.Hostname,
		ClientDroppedP0sWeight: float64(p.ClientDroppedP0s) / float64(len(p.Chunks())),
		GitCommitSha:           version.GetGitCommitShaFromTrace(root, chunk),
	}
	// TODO: We should find a way to not repeat container tags resolution downstream in the stats writer.
	// We will first need to deprecate the `enable_cid_stats` feature flag.
	gitCommitSha, imageTag, err := version.GetVersionDataFromContainerTags(containerID, conf)
	if err != nil {
		log.Debugf("Trace agent is unable to resolve container ID (%s) to container tags: %v", containerID, err)
	} else {
		pt.ImageTag = imageTag
		// Only override the GitCommitSha if it was not set in the trace.
		if pt.GitCommitSha == "" {
			pt.GitCommitSha = gitCommitSha
		}
	}
	return pt
}

// newChunksArray creates a new array which will point only to sampled chunks.
// The underlying array behind TracePayload.Chunks points to unsampled chunks
// preventing them from being collected by the GC.
func newChunksArray(chunks []*pb.TraceChunk) []*pb.TraceChunk {
	newChunks := make([]*pb.TraceChunk, len(chunks))
	copy(newChunks, chunks)
	return newChunks
}

var _ api.StatsProcessor = (*Agent)(nil)

// discardSpans removes all spans for which the provided DiscardFunction function returns true
func (a *Agent) discardSpans(p *api.Payload) {
	if a.DiscardSpan == nil {
		return
	}
	for _, chunk := range p.Chunks() {
		n := 0
		for _, span := range chunk.Spans {
			if !a.DiscardSpan(span) {
				chunk.Spans[n] = span
				n++
			}
		}
		// set everything at the back of the array to nil to avoid memory leaking
		// since we're going to have garbage elements at the back of the slice.
		for i := n; i < len(chunk.Spans); i++ {
			chunk.Spans[i] = nil
		}
		chunk.Spans = chunk.Spans[:n]
	}
}

func (a *Agent) processStats(in *pb.ClientStatsPayload, lang, tracerVersion string) *pb.ClientStatsPayload {
	enableContainers := a.conf.HasFeature("enable_cid_stats") || (a.conf.FargateOrchestrator != config.OrchestratorUnknown)
	if !enableContainers || a.conf.HasFeature("disable_cid_stats") {
		// only allow the ContainerID stats dimension if we're in a Fargate instance or it's
		// been explicitly enabled and it's not prohibited by the disable_cid_stats feature flag.
		in.ContainerID = ""
		in.Tags = nil
	}
	if in.Env == "" {
		in.Env = a.conf.DefaultEnv
	}
	in.Env = traceutil.NormalizeTag(in.Env)
	if in.TracerVersion == "" {
		in.TracerVersion = tracerVersion
	}
	if in.Lang == "" {
		in.Lang = lang
	}
	for i, group := range in.Stats {
		n := 0
		for _, b := range group.Stats {
			a.normalizeStatsGroup(b, lang)
			if !a.Blacklister.AllowsStat(b) {
				continue
			}
			a.obfuscateStatsGroup(b)
			a.Replacer.ReplaceStatsGroup(b)
			group.Stats[n] = b
			n++
		}
		in.Stats[i].Stats = group.Stats[:n]
		mergeDuplicates(in.Stats[i])
	}
	return in
}

func mergeDuplicates(s *pb.ClientStatsBucket) {
	indexes := make(map[stats.Aggregation]int, len(s.Stats))
	for i, g := range s.Stats {
		a := stats.NewAggregationFromGroup(g)
		if j, ok := indexes[a]; ok {
			s.Stats[j].Hits += g.Hits
			s.Stats[j].Errors += g.Errors
			s.Stats[j].Duration += g.Duration
			s.Stats[i].Hits = 0
			s.Stats[i].Errors = 0
			s.Stats[i].Duration = 0
		} else {
			indexes[a] = i
		}
	}
}

// ProcessStats processes incoming client stats in from the given tracer.
func (a *Agent) ProcessStats(in *pb.ClientStatsPayload, lang, tracerVersion string) {
	a.ClientStatsAggregator.In <- a.processStats(in, lang, tracerVersion)
}

// sample performs all sampling on the processedTrace modifying it as needed and returning if the trace should be kept and the number of events in the trace
func (a *Agent) sample(now time.Time, ts *info.TagStats, pt *traceutil.ProcessedTrace) (keep bool, numEvents int) {
	// We have a `keep` that is different from pt's `DroppedTrace` field as `DroppedTrace` will be sent to intake.
	// For example: We want to maintain the overall trace level sampling decision for a trace with Analytics Events
	// where a trace might be marked as DroppedTrace true, but we still sent analytics events in that ProcessedTrace.
	keep, checkAnalyticsEvents := a.traceSampling(now, ts, pt)

	var events []*pb.Span
	if checkAnalyticsEvents {
		events = a.getAnalyzedEvents(pt, ts)
	}
	if !keep {
		modified := sampler.SingleSpanSampling(pt)
		if !modified {
			// If there were no sampled spans, and we're not keeping the trace, let's use the analytics events
			// This is OK because SSS is a replacement for analytics events so both should not be configured
			// And when analytics events are fully gone we can get rid of all this
			pt.TraceChunk.Spans = events
		} else if len(events) > 0 {
			log.Warnf("Detected both analytics events AND single span sampling in the same trace. Single span sampling wins because App Analytics is deprecated.")
		}
	}

	return keep, len(events)
}

// isManualUserDrop returns true if and only if the ProcessedTrace is marked as Priority User Drop
// AND has a sampling decision maker of "Manual Sampling" (-4)
//
// Note: This does not work for traces with PriorityUserDrop, since most tracers do not set
// the decision maker field for user drop scenarios.
func isManualUserDrop(pt *traceutil.ProcessedTrace) bool {
	priority, _ := sampler.GetSamplingPriority(pt.TraceChunk)
	// Default priority is non-drop, so it's safe to ignore if the priority wasn't found
	if priority != sampler.PriorityUserDrop {
		return false
	}
	dm, hasDm := pt.TraceChunk.Tags[tagDecisionMaker]
	if !hasDm {
		return false
	}
	return dm == manualSampling
}

// traceSampling reports whether the chunk should be kept as a trace, setting "DroppedTrace" on the chunk
func (a *Agent) traceSampling(now time.Time, ts *info.TagStats, pt *traceutil.ProcessedTrace) (keep bool, checkAnalyticsEvents bool) {
	sampled, check := a.runSamplers(now, ts, *pt)
	pt.TraceChunk.DroppedTrace = !sampled
	return sampled, check
}

// getAnalyzedEvents returns any sampled analytics events in the ProcessedTrace
func (a *Agent) getAnalyzedEvents(pt *traceutil.ProcessedTrace, ts *info.TagStats) []*pb.Span {
	numEvents, numExtracted, events := a.EventProcessor.Process(pt)
	ts.EventsExtracted.Add(numExtracted)
	ts.EventsSampled.Add(numEvents)
	return events
}

// runSamplers runs the agent's configured samplers on pt and returns the sampling decision along
// with the sampling rate.
//
// The rare sampler is run first, catching all rare traces early. If the probabilistic sampler is
// enabled, it is run on the trace, followed by the error sampler. Otherwise, If the trace has a
// priority set, the sampling priority is used with the Priority Sampler. When there is no priority
// set, the NoPrioritySampler is run. Finally, if the trace has not been sampled by the other
// samplers, the error sampler is run.
func (a *Agent) runSamplers(now time.Time, ts *info.TagStats, pt traceutil.ProcessedTrace) (keep bool, checkAnalyticsEvents bool) {
	// run this early to make sure the signature gets counted by the RareSampler.
	rare := a.RareSampler.Sample(now, pt.TraceChunk, pt.TracerEnv)

	if a.conf.ProbabilisticSamplerEnabled {
		if rare {
			return true, true
		}
		if a.ProbabilisticSampler.Sample(pt.Root) {
			pt.TraceChunk.Tags[tagDecisionMaker] = probabilitySampling
			return true, true
		}
		if traceContainsError(pt.TraceChunk.Spans) {
			cleanUpExceptionSpanEventTag(pt.TraceChunk.Spans)
			return a.ErrorsSampler.Sample(now, pt.TraceChunk.Spans, pt.Root, pt.TracerEnv), true
		}
		return false, true
	}

	priority, hasPriority := sampler.GetSamplingPriority(pt.TraceChunk)
	if hasPriority {
		ts.TracesPerSamplingPriority.CountSamplingPriority(priority)
	} else {
		ts.TracesPriorityNone.Inc()
	}
	if a.conf.HasFeature("error_rare_sample_tracer_drop") {
		// We skip analytics events when a trace is marked as manual drop (aka priority -1)
		// Note that we DON'T skip single span sampling. We only do this for historical
		// reasons and analytics events are deprecated so hopefully this can all go away someday.
		if isManualUserDrop(&pt) {
			return false, false
		}
	} else { // This path to be deleted once manualUserDrop detection is available on all tracers for P < 1.
		if priority < 0 {
			return false, false
		}
	}

	if rare {
		return true, true
	}

	if hasPriority {
		if a.PrioritySampler.Sample(now, pt.TraceChunk, pt.Root, pt.TracerEnv, pt.ClientDroppedP0sWeight) {
			return true, true
		}
	} else if a.NoPrioritySampler.Sample(now, pt.TraceChunk.Spans, pt.Root, pt.TracerEnv) {
		return true, true
	}

	if traceContainsError(pt.TraceChunk.Spans) {
		cleanUpExceptionSpanEventTag(pt.TraceChunk.Spans)
		return a.ErrorsSampler.Sample(now, pt.TraceChunk.Spans, pt.Root, pt.TracerEnv), true
	}

	return false, true
}

func traceContainsError(trace pb.Trace) bool {
	for _, span := range trace {
		if spanIsError(span) {
			return true
		}
	}
	return false
}

func spanIsError(span *pb.Span) bool {
	return span.Error != 0 || spanContainsExceptionSpanEvent(span)
}

func spanContainsExceptionSpanEvent(span *pb.Span) bool {
	if hasExceptionSpanEvents, ok := span.Meta["_dd.span_events.has_exception"]; ok && hasExceptionSpanEvents == "true" {
		return true
	}
	return false
}

func cleanUpExceptionSpanEventTag(trace pb.Trace) {
	for _, span := range trace {
		delete(span.Meta, "_dd.span_events.has_exception")
	}
}

func filteredByTags(root *pb.Span, require, reject []*config.Tag, requireRegex, rejectRegex []*config.TagRegex) bool {
	for _, tag := range reject {
		if v, ok := root.Meta[tag.K]; ok && (tag.V == "" || v == tag.V) {
			return true
		}
	}
	for _, tag := range rejectRegex {
		if v, ok := root.Meta[tag.K]; ok && (tag.V == nil || tag.V.MatchString(v)) {
			return true
		}
	}
	for _, tag := range require {
		v, ok := root.Meta[tag.K]
		if !ok || (tag.V != "" && v != tag.V) {
			return true
		}
	}
	for _, tag := range requireRegex {
		v, ok := root.Meta[tag.K]
		if !ok || (tag.V != nil && !tag.V.MatchString(v)) {
			return true
		}
	}
	return false
}

func newEventProcessor(conf *config.AgentConfig, statsd statsd.ClientInterface) *event.Processor {
	extractors := []event.Extractor{event.NewMetricBasedExtractor()}
	if len(conf.AnalyzedSpansByService) > 0 {
		extractors = append(extractors, event.NewFixedRateExtractor(conf.AnalyzedSpansByService))
	} else if len(conf.AnalyzedRateByServiceLegacy) > 0 {
		extractors = append(extractors, event.NewLegacyExtractor(conf.AnalyzedRateByServiceLegacy))
	}

	return event.NewProcessor(extractors, conf.MaxEPS, statsd)
}

// SetGlobalTagsUnsafe sets global tags to the agent configuration. Unsafe for concurrent use.
func (a *Agent) SetGlobalTagsUnsafe(tags map[string]string) {
	a.conf.GlobalTags = tags
}
