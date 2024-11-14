// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.

//go:build test

// Package fx provides the tagger fx mock component
package fx

import (
	fakeimpl "github.com/DataDog/datadog-agent/comp/core/tagger/impl-fake"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

// team: container-platform

// MockModule defines the fx options for the mock component.
func MockModule() fxutil.Module {
	return fxutil.Component(
		fxutil.ProvideComponentConstructor(fakeimpl.NewComponent),
	)
}
