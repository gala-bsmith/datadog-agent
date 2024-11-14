package haagentimpl

import (
	"testing"

	"github.com/DataDog/datadog-agent/comp/core/config"
	logmock "github.com/DataDog/datadog-agent/comp/core/log/mock"
	haagent "github.com/DataDog/datadog-agent/comp/haagent/def"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx"
)

func newTestComponent(t *testing.T, overrides map[string]interface{}) haagent.Component {
	logComponent := logmock.New(t)
	config := fxutil.Test[config.Component](t, fx.Options(
		config.MockModule(),
		fx.Replace(config.MockParams{Overrides: overrides}),
	))

	requires := Requires{
		Logger:      logComponent,
		AgentConfig: config,
	}

	provides, err := NewComponent(requires)
	require.NoError(t, err)

	comp := provides.Comp
	require.NotNil(t, comp)
	return comp
}
