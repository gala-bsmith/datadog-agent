// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package haagent handles states for HA Agent feature.
package haagent

// team: network-device-monitoring

// Component is the component type.
type Component interface {
	Enabled() bool
	GetGroup() string
	IsLeader() bool
	SetLeader(leaderAgentHostname string)
}
