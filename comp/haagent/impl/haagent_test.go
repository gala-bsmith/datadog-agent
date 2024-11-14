package haagentimpl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Enabled(t *testing.T) {
	tests := []struct {
		name            string
		configs         map[string]interface{}
		expectedEnabled bool
	}{
		{
			name: "enabled",
			configs: map[string]interface{}{
				"ha_agent.enabled": true,
			},
			expectedEnabled: true,
		},
		{
			name: "disabled",
			configs: map[string]interface{}{
				"ha_agent.enabled": false,
			},
			expectedEnabled: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			comp := newTestComponent(t, tt.configs)
			assert.Equal(t, tt.expectedEnabled, comp.Enabled())
		})
	}
}

func Test_IsLeader_SetLeader(t *testing.T) {
	overrides := map[string]interface{}{
		"hostname":                 "my-agent-hostname",
		"ha_agent.expectedEnabled": true,
	}
	comp := newTestComponent(t, overrides)

	comp.SetLeader("another-agent")
	assert.False(t, comp.IsLeader())

	comp.SetLeader("my-agent-hostname")
	assert.True(t, comp.IsLeader())
}
