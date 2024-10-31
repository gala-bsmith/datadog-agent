// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package discovery

import (
	_ "embed"
	"testing"
	"time"

	"github.com/DataDog/datadog-agent/test/fakeintake/aggregator"
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/e2e"
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/environments"
	awsdocker "github.com/DataDog/datadog-agent/test/new-e2e/pkg/environments/aws/docker"
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/utils/e2e/client/agentclient"
	"github.com/DataDog/test-infra-definitions/components/datadog/dockeragentparams"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/docker/python_server.yaml
var pythonServerCompose string

type dockerDiscoveryTestSuite struct {
	e2e.BaseSuite[environments.DockerHost]
}

func TestDiscoveryDocker(t *testing.T) {
	agentOpts := []dockeragentparams.Option{
		dockeragentparams.WithAgentServiceEnvVariable("DD_DISCOVERY_ENABLED", pulumi.StringPtr("true")),
		dockeragentparams.WithExtraComposeManifest("pythonServer", pulumi.String(pythonServerCompose)),
	}

	e2e.Run(t,
		&dockerDiscoveryTestSuite{},
		e2e.WithProvisioner(
			awsdocker.Provisioner(
				awsdocker.WithAgentOptions(agentOpts...),
			)))
}

func (s *dockerDiscoveryTestSuite) TestServiceDiscoveryCheck() {
	t := s.T()

	client := s.Env().FakeIntake.Client()
	err := client.FlushServerAndResetAggregators()
	require.NoError(t, err)

	s.assertDockerAgentDiscoveryRunning()

	services := s.Env().Docker.Client.ExecuteCommand(s.Env().Agent.ContainerName, "curl", "-s", "--unix-socket", "/opt/datadog-agent/run/sysprobe.sock", "http://unix/discovery/services")
	t.Logf("system-probe services: %v", services)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		payloads, err := client.GetServiceDiscoveries()
		require.NoError(t, err)
		t.Logf("raw payload: %+v", payloads)

		foundMap := make(map[string]*aggregator.ServiceDiscoveryPayload)
		for _, p := range payloads {
			name := p.Payload.ServiceName
			t.Log("RequestType", p.RequestType, "ServiceName", name)

			if p.RequestType == "start-service" {
				foundMap[name] = p
			}
		}
		t.Logf("foundMap: %+v", foundMap)
		assert.NotEmpty(c, foundMap)
	}, 3*time.Minute, 10*time.Second)
}

func (s *dockerDiscoveryTestSuite) assertDockerAgentDiscoveryRunning() {
	t := s.T()

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		statusOutput := s.Env().Agent.Client.Status(agentclient.WithArgs([]string{"collector", "--json"})).Content
		assertCollectorStatusFromJSON(c, statusOutput, "service_discovery")
	}, 2*time.Minute, 10*time.Second)
}
