package haagentimpl

import log "github.com/DataDog/datadog-agent/comp/core/log/def"

type haAgentImpl struct {
	log            log.Component
	haAgentConfigs *haAgentConfigs
}

func newHaAgentImpl(log log.Component, haAgentConfigs *haAgentConfigs) *haAgentImpl {
	return &haAgentImpl{
		log:            log,
		haAgentConfigs: haAgentConfigs,
	}
}

func (h *haAgentImpl) IsLeader() bool {
	//TODO implement me
	panic("implement me")
}
