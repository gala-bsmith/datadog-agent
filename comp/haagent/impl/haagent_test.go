package haagentimpl

import (
	"testing"

	"github.com/DataDog/datadog-agent/comp/core/config"
	logmock "github.com/DataDog/datadog-agent/comp/core/log/mock"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
	"github.com/stretchr/testify/assert"
	"go.uber.org/fx"
)

func TestServer(t *testing.T) {
	logComponent := logmock.New(t)

	overrides := map[string]interface{}{
		"ha_agent.enabled": true,
	}
	config := fxutil.Test[config.Component](t, fx.Options(
		config.MockModule(),
		fx.Replace(config.MockParams{Overrides: overrides}),
	))

	requires := Requires{
		Logger:      logComponent,
		AgentConfig: config,
	}

	provides, err := NewComponent(requires)

	assert.NoError(t, err)

	assert.NotNil(t, provides.Comp)

	provides.Comp.SetLeader("abc")
	assert.False(t, provides.Comp.IsLeader())
}
