// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

//go:build !linux && !windows

package server

// NewListener is not supported
func NewListener(_ string) (Listener, error) {
	return nil, ErrNotImplemented
}
