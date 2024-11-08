// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !linux

// Package tags holds tags related files
package tags

import (
	"github.com/DataDog/datadog-agent/comp/core/telemetry"
	"github.com/DataDog/datadog-agent/pkg/security/probe/config"
)

// Listener is used to propagate tags events
type Listener func(workload interface{})

// NewResolver returns a new tags resolver
func NewResolver(config *config.Config, telemetry telemetry.Component) Resolver {
	return NewDefaultResolver(config, telemetry)
}
