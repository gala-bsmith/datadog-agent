// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package tags holds tags related files
package tags

import (
	"context"
	"fmt"
	"strings"

	coreconfig "github.com/DataDog/datadog-agent/comp/core/config"
	tagger "github.com/DataDog/datadog-agent/comp/core/tagger/def"
	remoteTagger "github.com/DataDog/datadog-agent/comp/core/tagger/impl-remote"
	"github.com/DataDog/datadog-agent/comp/core/tagger/types"
	"github.com/DataDog/datadog-agent/comp/core/telemetry"
	"github.com/DataDog/datadog-agent/pkg/api/security"
	pkgconfigsetup "github.com/DataDog/datadog-agent/pkg/config/setup"
	"github.com/DataDog/datadog-agent/pkg/security/probe/config"
	"github.com/DataDog/datadog-agent/pkg/security/utils"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// Tagger defines a Tagger for the Tags Resolver
type Tagger interface {
	Start(ctx context.Context) error
	Stop() error
	Tag(entity types.EntityID, cardinality types.TagCardinality) ([]string, error)
}

type nullTagger struct{}

func (n *nullTagger) Start(_ context.Context) error {
	return nil
}

func (n *nullTagger) Stop() error {
	return nil
}

func (n *nullTagger) Tag(_ types.EntityID, _ types.TagCardinality) ([]string, error) {
	return nil, nil
}

// Resolver represents a cache resolver
type Resolver interface {
	Start(ctx context.Context) error
	Stop() error
	Resolve(id string) []string
	ResolveWithErr(id string) ([]string, error)
	GetValue(id string, tag string) string
}

// DefaultResolver represents a default resolver based directly on the underlying tagger
type DefaultResolver struct {
	tagger Tagger
}

// Start the resolver
func (t *DefaultResolver) Start(ctx context.Context) error {
	go func() {
		if err := t.tagger.Start(ctx); err != nil {
			log.Errorf("failed to init tagger: %s", err)
		}
	}()

	go func() {
		<-ctx.Done()
		_ = t.tagger.Stop()
	}()

	return nil
}

// Resolve returns the tags for the given id
func (t *DefaultResolver) Resolve(id string) []string {
	// container id for ecs task are composed of task id + container id.
	// use only the container id part for the tag resolution.
	if els := strings.Split(id, "-"); len(els) == 2 {
		id = els[1]
	}

	entityID := types.NewEntityID(types.ContainerID, id)
	tags, _ := t.tagger.Tag(entityID, types.OrchestratorCardinality)
	return tags
}

// ResolveWithErr returns the tags for the given id
func (t *DefaultResolver) ResolveWithErr(id string) ([]string, error) {
	entityID := types.NewEntityID(types.ContainerID, id)
	return t.tagger.Tag(entityID, types.OrchestratorCardinality)
}

// GetValue return the tag value for the given id and tag name
func (t *DefaultResolver) GetValue(id string, tag string) string {
	return utils.GetTagValue(tag, t.Resolve(id))
}

// Stop the resolver
func (t *DefaultResolver) Stop() error {
	return t.tagger.Stop()
}

// NewResolver returns a new tags resolver
func NewResolver(config *config.Config, telemetry telemetry.Component) Resolver {
	ddConfig := pkgconfigsetup.Datadog()

	if config.RemoteTaggerEnabled {
		params := tagger.RemoteParams{
			RemoteFilter: types.NewMatchAllFilter(),
			RemoteTarget: func(c coreconfig.Component) (string, error) { return fmt.Sprintf(":%v", c.GetInt("cmd_port")), nil },
			RemoteTokenFetcher: func(c coreconfig.Component) func() (string, error) {
				return func() (string, error) {
					return security.FetchAuthToken(c)
				}
			},
		}

		tagger, _ := remoteTagger.NewRemoteTagger(params, ddConfig, log.NewWrapper(2), telemetry)

		return &DefaultResolver{
			// TODO: (components) use the actual remote tagger instance from the Fx entry point
			tagger: tagger,
		}
	}
	return &DefaultResolver{
		tagger: &nullTagger{},
	}
}
