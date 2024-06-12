// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package servicediscovery

import (
	_ "embed"
	"encoding/json"
	"github.com/DataDog/datadog-agent/test/fakeintake/aggregator"
	"github.com/DataDog/test-infra-definitions/components/datadog/agentparams"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/components"
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/e2e"
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/environments"
	awshost "github.com/DataDog/datadog-agent/test/new-e2e/pkg/environments/aws/host"
)

//go:embed testdata/config/agent_config.yaml
var agentConfigStr string

type linuxTestSuite struct {
	e2e.BaseSuite[environments.Host]
}

func TestLinuxTestSuite(t *testing.T) {
	agentParams := []func(*agentparams.Params) error{
		agentparams.WithAgentConfig(agentConfigStr),
	}
	options := []e2e.SuiteOption{
		e2e.WithProvisioner(awshost.Provisioner(awshost.WithAgentOptions(agentParams...))),
	}
	devModeEnv, _ := os.LookupEnv("E2E_DEVMODE")
	if devMode, err := strconv.ParseBool(devModeEnv); err == nil && devMode {
		options = append(options, e2e.WithDevMode())
	}
	e2e.Run(t, &linuxTestSuite{}, options...)
}

func (s *linuxTestSuite) SetupSuite() {
	s.BaseSuite.SetupSuite()

	s.provisionServer()
}

func (s *linuxTestSuite) TestServiceDiscoveryCheck() {
	t := s.T()
	s.startServices()
	defer s.stopServices()

	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		assertRunningChecks(t, s.Env().RemoteHost, []string{"service_discovery"})
	}, 2*time.Minute, 5*time.Second)

	var payloads []*aggregator.ServiceDiscoveryPayload
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		var err error
		payloads, err = s.Env().FakeIntake.Client().GetServiceDiscoveries()
		assert.NoError(c, err, "failed to get service discovery payloads from fakeintake")

		// Wait for 3 payloads, as services must be detected in two check runs to be returned
		assert.GreaterOrEqual(c, len(payloads), 3, "fewer than 2 payloads returned")
	}, 5*time.Minute, 10*time.Second)

	// TODO: check payloads
}

type checkStatus struct {
	CheckID           string `json:"CheckID"`
	CheckName         string `json:"CheckName"`
	CheckConfigSource string `json:"CheckConfigSource"`
	ExecutionTimes    []int  `json:"ExecutionTimes"`
}

type runnerStats struct {
	Checks map[string]checkStatus `json:"Checks"`
}

type collectorStatus struct {
	RunnerStats runnerStats `json:"runnerStats"`
}

// assertRunningChecks asserts that the given process agent checks are running on the given VM
func assertRunningChecks(t *assert.CollectT, remoteHost *components.RemoteHost, checks []string) {
	statusOutput := remoteHost.MustExecute("sudo datadog-agent status collector --json")

	var status collectorStatus
	err := json.Unmarshal([]byte(statusOutput), &status)
	require.NoError(t, err, "failed to unmarshal agent status")

	for _, c := range checks {
		assert.Contains(t, status.RunnerStats.Checks, c)
	}
}

func (s *linuxTestSuite) provisionServer() {
	err := s.Env().RemoteHost.CopyFolder("testdata/provision", "/home/ubuntu/e2e-test")
	require.NoError(s.T(), err)
	s.Env().RemoteHost.MustExecute("sudo bash /home/ubuntu/e2e-test/provision.sh")
}

func (s *linuxTestSuite) startServices() {
	s.Env().RemoteHost.MustExecute("sudo systemctl start go-svc")
	s.Env().RemoteHost.MustExecute("sudo systemctl start node-svc")
	s.Env().RemoteHost.MustExecute("sudo systemctl start python-svc")
}

func (s *linuxTestSuite) stopServices() {
	s.Env().RemoteHost.MustExecute("sudo systemctl stop go-svc")
	s.Env().RemoteHost.MustExecute("sudo systemctl stop node-svc")
	s.Env().RemoteHost.MustExecute("sudo systemctl stop python-svc")
}
