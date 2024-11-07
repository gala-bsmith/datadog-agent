// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package module

import (
	"net/http"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/process"

	"github.com/DataDog/datadog-agent/cmd/system-probe/api/module"
	sysconfigtypes "github.com/DataDog/datadog-agent/cmd/system-probe/config/types"
	"github.com/DataDog/datadog-agent/cmd/system-probe/utils"

	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/servicediscovery"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/servicediscovery/apm"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/servicediscovery/envs"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/servicediscovery/language"

	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/servicediscovery/model"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/servicediscovery/usm"

	"github.com/DataDog/datadog-agent/pkg/process/procutil"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/util/winutil/iphelper"
)

const (
	pathServices = "/services"
)

// Ensure discovery implements the module.Module interface.
var _ module.Module = &discovery{}

// serviceInfo caches static data about a process.
type serviceInfo struct {
	generatedName      string
	ddServiceName      string
	ddServiceInjected  bool
	language           language.Language
	apmInstrumentation apm.Instrumentation
	cmdLine            []string
	startTimeMillis    uint64
	lastCPUUsage       float64
}

type resourceInfo struct {
	cpuUsage float64
	rss      uint64
	ports    []uint16
}

// discovery is an implementation of the Module interface for the discovery module.
type discovery struct {
	mux *sync.RWMutex
	// cache maps pids to data that should be cached between calls to the endpoint.
	cache map[int32]*serviceInfo

	// scrubber is used to remove potentially sensitive data from the command line
	scrubber *procutil.DataScrubber

	lastTotalSystemCPUUsage float64
}

// NewDiscoveryModule creates a new discovery system probe module.
func NewDiscoveryModule(*sysconfigtypes.Config, module.FactoryDependencies) (module.Module, error) {
	return &discovery{
		mux:      &sync.RWMutex{},
		cache:    make(map[int32]*serviceInfo),
		scrubber: procutil.NewDefaultDataScrubber(),
	}, nil
}

// GetStats returns the stats of the discovery module.
func (s *discovery) GetStats() map[string]interface{} {
	return nil
}

// Register registers the discovery module with the provided HTTP mux.
func (s *discovery) Register(httpMux *module.Router) error {
	httpMux.HandleFunc("/status", s.handleStatusEndpoint)
	httpMux.HandleFunc(pathServices, utils.WithConcurrencyLimit(utils.DefaultMaxConcurrentRequests, s.handleServices))
	return nil
}

// Close cleans resources used by the discovery module.
func (s *discovery) Close() {
	s.mux.Lock()
	defer s.mux.Unlock()
	clear(s.cache)
}

// handleStatusEndpoint is the handler for the /status endpoint.
// Reports the status of the discovery module.
func (s *discovery) handleStatusEndpoint(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("Discovery Module is running"))
}

// handleServers is the handler for the /services endpoint.
// Returns the list of currently running services.
func (s *discovery) handleServices(w http.ResponseWriter, _ *http.Request) {
	services, err := s.getServices()
	if err != nil {
		_ = log.Errorf("failed to handle /discovery%s: %v", pathServices, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp := &model.ServicesResponse{
		Services: *services,
	}
	utils.WriteAsJSON(w, resp)
}

// getServices returns the list of currently running services.
func (s *discovery) getServices() (*[]model.Service, error) {
	// Get a snapshot of the total system CPU usage.
	// This calls Win32 GetSystemTimes
	systemStats, err := cpu.Times(false)
	if err != nil {
		return nil, err
	}
	totalSystemCPUUsage := systemStats[0].User + systemStats[0].System
	systemCPUUsageDelta := totalSystemCPUUsage - s.lastTotalSystemCPUUsage

	// Get all current live processes.
	// This calls Win32 EnumProcess
	pids, err := process.Pids()
	if err != nil {
		return nil, err
	}

	newServiceInfos := make(map[int32]*serviceInfo, len(pids))
	var services []model.Service

	// Query all opened TCP ports.
	tcpTable, err := iphelper.GetExtendedTcpV4Table()
	if err != nil {
		return nil, err
	}

	for _, pid := range pids {
		// Query static process information. This may be cached.
		serviceInfo, err := s.getServiceInfo(pid)
		if err != nil {
			continue
		}

		// Query resource usage by the process at this time.
		resInfo, err := queryResourceInfo(pid, tcpTable)
		if err != nil {
			continue
		}

		newServiceInfos[pid] = serviceInfo

		// Compile a snapshot to report to the cloud.
		service, err := s.buildServiceSnapshot(pid, serviceInfo, resInfo, systemCPUUsageDelta)
		if err != nil {
			continue
		}

		// Save the CPU usage for the next iteration.
		serviceInfo.lastCPUUsage = resInfo.cpuUsage

		services = append(services, *service)
	}

	// Save the total system CPU usage for the next iteration.
	s.lastTotalSystemCPUUsage = totalSystemCPUUsage

	s.cleanCache(newServiceInfos)

	return &services, nil
}

func (s *discovery) getServiceInfo(pid int32) (*serviceInfo, error) {
	// This also fetches createTime with Win32 GetProcessTimes
	proc, err := process.NewProcess(pid)
	if err != nil {
		return nil, err
	}

	// Check if the process was previously detected.
	cachedInfo, ok := s.getCachedInfo(proc)
	if ok {
		return cachedInfo, nil
	}

	// Fetch createTime from the process. This should already be cached.
	createTimeMs, err := proc.CreateTime()
	if err != nil {
		createTimeMs = 0
	}

	// TODO: Filter processes to never report.
	// This calls Win32 QueryFullProcessImageName.
	//imageName, err := proc.Name()
	//if err != nil {
	//	return nil, err
	//}

	// This calls Win32 GetUserProcessParams and then ReadProcessMemory to
	// extract the command line from the PEB.
	cmdline, err := proc.CmdlineSlice()
	if err != nil {
		return nil, err
	}
	cmdline, _ = s.scrubber.ScrubCommand(cmdline)

	// This calls Win32 QueryFullProcessImageName
	exe, err := proc.Exe()
	if err != nil {
		return nil, err
	}

	envVars, err := getEnvVars(proc)
	if err != nil {
		return nil, err
	}

	// rootDir has no effect for GetServiceName since USM has only Linux executable detectors.
	rootDir := filepath.Dir(exe)

	contextMap := make(usm.DetectorContextMap)
	contextMap[usm.ServiceProc] = proc

	fs := usm.NewSubDirFS(rootDir)
	ctx := usm.NewDetectionContext(cmdline, envVars, fs)
	ctx.Pid = int(proc.Pid)
	ctx.ContextMap = contextMap

	// Try to detect the runtime language of process.
	lang := language.FindInArgs(exe, cmdline)

	nameMeta := servicediscovery.GetServiceName(lang, ctx)
	apmInstrumentation := apm.Detect(lang, ctx)

	// This is static process information
	return &serviceInfo{
			generatedName:      nameMeta.Name,
			ddServiceName:      nameMeta.DDService,
			ddServiceInjected:  nameMeta.DDServiceInjected,
			apmInstrumentation: apmInstrumentation,
			language:           lang,
			cmdLine:            cmdline,
			startTimeMillis:    uint64(createTimeMs),
		},
		nil
}

// queryResourceInfo queries for CPU usage and working set of the given process.
func queryResourceInfo(pid int32, tcpTable map[uint32][]iphelper.MIB_TCPROW_OWNER_PID) (*resourceInfo, error) {
	// We do not call process.NewProcess because it does a few expensive checks that we don't need.
	proc := &process.Process{
		Pid: pid,
	}

	// This calls Win32 GetProcessMemoryInfo with the working set.
	memInfo, err := proc.MemoryInfo()
	if err != nil {
		return nil, err
	}

	// This calls Win32 GetProcessTimes with CPU usage.
	cpuTimes, err := proc.Times()
	if err != nil {
		return nil, err
	}

	// Find the reserved TCP ports by this PID.
	var ports []uint16
	var entries = tcpTable[uint32(pid)]
	for _, entry := range entries {
		ports = append(ports, uint16(entry.DwLocalPort))
	}

	return &resourceInfo{
		// CPU user and system (kernel) times are in seconds.
		cpuUsage: cpuTimes.User + cpuTimes.System,

		// RSS is the same as the working set.
		rss: memInfo.RSS,

		ports: ports,
	}, nil
}

func (s *discovery) buildServiceSnapshot(pid int32, serviceInfo *serviceInfo, resInfo *resourceInfo, systemCPUsageDelta float64) (*model.Service, error) {
	// Preferred the name from DD_TAGS.
	preferredName := serviceInfo.ddServiceName
	if preferredName == "" {
		preferredName = serviceInfo.generatedName
	}

	// Compute average CPU core usage.
	procCPUUsageDelta := resInfo.cpuUsage - serviceInfo.lastCPUUsage
	avgCPUCores := (procCPUUsageDelta / systemCPUsageDelta) * float64(runtime.NumCPU())

	return &model.Service{
		// Static information
		PID:                int(pid),
		Name:               preferredName,
		GeneratedName:      serviceInfo.generatedName,
		DDService:          serviceInfo.ddServiceName,
		DDServiceInjected:  serviceInfo.ddServiceInjected,
		APMInstrumentation: string(serviceInfo.apmInstrumentation),
		Language:           string(serviceInfo.language),
		CommandLine:        serviceInfo.cmdLine,
		StartTimeMilli:     serviceInfo.startTimeMillis,

		// Resource information
		RSS:      resInfo.rss,
		CPUCores: avgCPUCores,
		Ports:    resInfo.ports,
	}, nil
}

func (s *discovery) getCachedInfo(proc *process.Process) (*serviceInfo, bool) {
	s.mux.RLock()
	service, ok := s.cache[proc.Pid]
	s.mux.RUnlock()

	if ok {
		// PIDs can be randomly reused. Check if this process matches the same start time.
		createTimeMs, err := proc.CreateTime()
		if err != nil && (uint64(createTimeMs) == service.startTimeMillis) {
			return service, true
		}
	}

	return nil, false
}

// getEnvs gets the environment variables for the process, both the initial
// ones, and if present, the ones injected via the auto injector.
func getEnvVars(proc *process.Process) (envs.Variables, error) {
	var envVars = envs.Variables{}

	// This calls Win32 GetProcessEnvironmentVariables
	procEnvs, err := proc.Environ()
	if err != nil {
		return envVars, err
	}

	// Split the name/value pairs.
	for _, env := range procEnvs {
		name, value, found := strings.Cut(env, "=")
		if found {
			envVars.Set(name, value)
		}
	}

	return envVars, nil
}

// ignoreComms is a list of process names (matched against /proc/PID/comm) to
// never report as a service. Note that comm is limited to 16 characters.
/*
var ignoreComms = map[string]struct{}{
	"sshd":             {},
	"dhclient":         {},
	"systemd":          {},
	"systemd-resolved": {},
	"systemd-networkd": {},
	"datadog-agent":    {},
	"livenessprobe":    {},
	"docker-proxy":     {},
}
*/

// cleanCache deletes dead PIDs from the cache. Note that this does not actually
// shrink the map but should free memory for the service name strings referenced
// from it.
func (s *discovery) cleanCache(newServiceInfos map[int32]*serviceInfo) {
	s.mux.Lock()
	defer s.mux.Unlock()

	reusedPids := map[int32]*serviceInfo{}

	for pid, oldInfo := range s.cache {
		if newInfo, alive := newServiceInfos[pid]; alive {
			// PIDs can be reused.  Keep the info only if the start time matches.
			if oldInfo.startTimeMillis == newInfo.startTimeMillis {
				continue
			}

			// This is a reused PID.Replace the info after we are done cleaning up.
			reusedPids[pid] = newInfo
		}

		delete(s.cache, pid)
	}

	// Replace reused PIDs (if any)
	for pid, newInfo := range reusedPids {
		s.cache[pid] = newInfo
	}
}
