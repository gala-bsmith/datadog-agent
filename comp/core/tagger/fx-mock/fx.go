// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.

//go:build test

// Package fx provides the tagger fx mock component
package fx

import (
	"go.uber.org/fx"

	tagger "github.com/DataDog/datadog-agent/comp/core/tagger/def"
	fakeimpl "github.com/DataDog/datadog-agent/comp/core/tagger/impl-fake"
	taggermock "github.com/DataDog/datadog-agent/comp/core/tagger/mock"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
	"github.com/DataDog/datadog-agent/pkg/util/optional"
)

// team: container-platform

// MockModule defines the fx options for the mock component.
func MockModule() fxutil.Module {
	return fxutil.Component(
		fxutil.ProvideComponentConstructor(fakeimpl.NewComponent),
		fx.Provide(func(mock taggermock.Mock) tagger.Component { return mock }),
		fx.Provide(func(mock taggermock.Mock) optional.Option[tagger.Component] {
			return optional.NewOption[tagger.Component](mock)
		}),
	)
}
