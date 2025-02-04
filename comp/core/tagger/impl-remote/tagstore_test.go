// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package remotetaggerimpl

import (
	"testing"

	"github.com/stretchr/testify/assert"

	taggerTelemetry "github.com/DataDog/datadog-agent/comp/core/tagger/telemetry"
	"github.com/DataDog/datadog-agent/comp/core/tagger/types"
	"github.com/DataDog/datadog-agent/comp/core/telemetry"
	"github.com/DataDog/datadog-agent/comp/core/telemetry/telemetryimpl"
	configmock "github.com/DataDog/datadog-agent/pkg/config/mock"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

var (
	entityID        types.EntityID = types.NewEntityID("foo", "bar")
	anotherEntityID types.EntityID = types.NewEntityID("foo", "quux")
)

func TestProcessEvent_AddAndModify(t *testing.T) {
	events := []types.EntityEvent{
		{
			EventType: types.EventTypeAdded,
			Entity: types.Entity{
				ID:                 entityID,
				LowCardinalityTags: []string{"foo"},
			},
		},
		{
			EventType: types.EventTypeModified,
			Entity: types.Entity{
				ID:                          entityID,
				LowCardinalityTags:          []string{"foo", "bar"},
				OrchestratorCardinalityTags: []string{"baz"},
			},
		},
		{
			EventType: types.EventTypeAdded,
			Entity: types.Entity{
				ID:                 anotherEntityID,
				LowCardinalityTags: []string{"quux"},
			},
		},
	}
	tel := fxutil.Test[telemetry.Component](t, telemetryimpl.MockModule())
	telemetryStore := taggerTelemetry.NewStore(tel)
	cfg := configmock.New(t)
	store := newTagStore(cfg, telemetryStore)
	store.processEvents(events, false)

	entity := store.getEntity(entityID)

	assert.Equal(t, []string{"foo", "bar"}, entity.LowCardinalityTags)
	assert.Equal(t, []string{"baz"}, entity.OrchestratorCardinalityTags)
	assert.Equal(t, []string(nil), entity.HighCardinalityTags)
	assert.Equal(t, []string(nil), entity.StandardTags)
}

func TestProcessEvent_AddAndDelete(t *testing.T) {
	events := []types.EntityEvent{
		{
			EventType: types.EventTypeAdded,
			Entity: types.Entity{
				ID:                 entityID,
				LowCardinalityTags: []string{"foo"},
			},
		},
		{
			EventType: types.EventTypeAdded,
			Entity: types.Entity{
				ID:                 anotherEntityID,
				LowCardinalityTags: []string{"quux"},
			},
		},
		{
			EventType: types.EventTypeDeleted,
			Entity: types.Entity{
				ID: entityID,
			},
		},
	}

	tel := fxutil.Test[telemetry.Component](t, telemetryimpl.MockModule())
	telemetryStore := taggerTelemetry.NewStore(tel)
	cfg := configmock.New(t)
	store := newTagStore(cfg, telemetryStore)
	store.processEvents(events, false)

	entity := store.getEntity(entityID)

	assert.Nil(t, entity)

	entity = store.getEntity(anotherEntityID)

	assert.NotNil(t, entity)
}

func TestProcessEvent_Replace(t *testing.T) {
	tel := fxutil.Test[telemetry.Component](t, telemetryimpl.MockModule())
	cfg := configmock.New(t)
	telemetryStore := taggerTelemetry.NewStore(tel)
	store := newTagStore(cfg, telemetryStore)

	store.processEvents([]types.EntityEvent{
		{
			EventType: types.EventTypeAdded,
			Entity: types.Entity{
				ID:                 entityID,
				LowCardinalityTags: []string{"foo"},
			},
		},
	}, false)

	store.processEvents([]types.EntityEvent{
		{
			EventType: types.EventTypeAdded,
			Entity: types.Entity{
				ID:                 anotherEntityID,
				LowCardinalityTags: []string{"foo"},
			},
		},
	}, true)

	entity := store.getEntity(entityID)

	assert.Nil(t, entity)

	entity = store.getEntity(anotherEntityID)

	assert.NotNil(t, entity)
}
