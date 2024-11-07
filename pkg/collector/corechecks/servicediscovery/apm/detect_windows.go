// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package apm provides functionality to detect the type of APM instrumentation a service is using.
package apm

import (
	"strings"

	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/servicediscovery/envs"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/servicediscovery/language"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/servicediscovery/usm"
)

// Instrumentation represents the state of APM instrumentation for a service.
type Instrumentation string

const (
	// None means the service is not instrumented with APM.
	None Instrumentation = "none"
	// Provided means the service has been manually instrumented.
	Provided Instrumentation = "provided"
	// Injected means the service is using automatic APM injection.
	Injected Instrumentation = "injected"
)

// Detect attempts to detect the type of APM instrumentation for the given service.
func Detect(_ language.Language, ctx usm.DetectionContext) Instrumentation {
	// first check to see if the DD_INJECTION_ENABLED is set to tracer
	if isInjected(ctx.Envs) {
		return Injected
	}

	return None
}

func isInjected(envs envs.Variables) bool {
	if val, ok := envs.Get("DD_INJECTION_ENABLED"); ok {
		parts := strings.Split(val, ",")
		for _, v := range parts {
			if v == "tracer" {
				return true
			}
		}
	}
	return false
}
