package haagentimpl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestServer(t *testing.T) {

	overrides := map[string]interface{}{
		"hostname":         "my-agent-hostname",
		"ha_agent.enabled": true,
	}

	comp := newTestComponent(t, overrides)

	assert.NotNil(t, comp)

	comp.SetLeader("another-agent")
	assert.False(t, comp.IsLeader())

	comp.SetLeader("my-agent-hostname")
	assert.True(t, comp.IsLeader())
}
