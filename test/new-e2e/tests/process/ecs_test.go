// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package process

import (
	"testing"
	"time"

	"github.com/DataDog/test-infra-definitions/common/config"
	"github.com/DataDog/test-infra-definitions/components/datadog/apps/cpustress"
	"github.com/DataDog/test-infra-definitions/components/datadog/apps/nginx"
	"github.com/DataDog/test-infra-definitions/components/datadog/apps/redis"
	"github.com/DataDog/test-infra-definitions/components/datadog/ecsagentparams"
	fakeintakeComp "github.com/DataDog/test-infra-definitions/components/datadog/fakeintake"
	"github.com/DataDog/test-infra-definitions/resources/aws"
	"github.com/DataDog/test-infra-definitions/scenarios/aws/fakeintake"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/ssm"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-agent/test/fakeintake/aggregator"
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/e2e"
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/environments"
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/environments/aws/ecs"
)

type ECSSuite struct {
	e2e.BaseSuite[ecsCPUStressEnv]
}

type ecsCPUStressEnv struct {
	environments.ECS
}

func ecsCPUStressProvisioner() e2e.PulumiEnvRunFunc[ecsCPUStressEnv] {
	return func(ctx *pulumi.Context, env *ecsCPUStressEnv) error {
		awsEnv, err := aws.NewEnvironment(ctx)
		if err != nil {
			return err
		}
		env.ECS.AwsEnvironment = &awsEnv

		params := ecs.GetProvisionerParams(
			//ecs.WithECSLinuxECSOptimizedNodeGroup(),
			ecs.WithECSFargateCapacityProvider(),
			ecs.WithAgentOptions(
				ecsagentparams.WithAgentServiceEnvVariable("DD_PROCESS_CONFIG_PROCESS_COLLECTION_ENABLED", "true"),
			),
		)

		if err := ecs.Run(ctx, &env.ECS, params); err != nil {
			return err
		}

		if _, err := cpustress.EcsAppDefinition(awsEnv, env.ClusterArn); err != nil {
			return err
		}

		var fakeIntake *fakeintakeComp.Fakeintake
		if fakeIntake, err = fakeintake.NewECSFargateInstance(awsEnv, "ecs"); err != nil {
			return err
		}
		if err := fakeIntake.Export(awsEnv.Ctx(), nil); err != nil {
			return err
		}

		apiKeyParam, err := ssm.NewParameter(ctx, awsEnv.Namer.ResourceName("agent-apikey"), &ssm.ParameterArgs{
			Name:      awsEnv.CommonNamer().DisplayName(1011, pulumi.String("agent-apikey")),
			Type:      ssm.ParameterTypeSecureString,
			Overwrite: pulumi.Bool(true),
			Value:     awsEnv.AgentAPIKey(),
		}, awsEnv.WithProviders(config.ProviderAWS))

		// Deploy Fargate Agents
		if _, err := redis.FargateAppDefinition(awsEnv, env.ClusterArn, apiKeyParam.Name, fakeIntake); err != nil {
			return err
		}

		if _, err = nginx.FargateAppDefinition(awsEnv, env.ClusterArn, apiKeyParam.Name, fakeIntake); err != nil {
			return err
		}

		return nil
	}
}

func TestECSTestSuite(t *testing.T) {
	t.Parallel()
	s := ECSSuite{}
	e2eParams := []e2e.SuiteOption{e2e.WithProvisioner(
		e2e.NewTypedPulumiProvisioner("ecsCPUStress", ecsCPUStressProvisioner(), nil))}

	e2e.Run(t, &s, e2eParams...)
}

func (s *ECSSuite) TestECSProcessCheck() {
	t := s.T()

	var payloads []*aggregator.ProcessPayload
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		var err error
		payloads, err = s.Env().FakeIntake.Client().GetProcesses()
		assert.NoError(c, err, "failed to get process payloads from fakeintake")

		// Wait for two payloads, as processes must be detected in two check runs to be returned
		assert.GreaterOrEqual(c, len(payloads), 2, "fewer than 2 payloads returned")
	}, 2*time.Minute, 10*time.Second)

	assertProcessCollected(t, payloads, false, "stress-ng-cpu [run]")
	assertContainersCollected(t, payloads, []string{"stress-ng"})
}
