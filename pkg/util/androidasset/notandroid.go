// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !android
// +build !android

package androidasset

import "github.com/DataDog/datadog-agent/pkg/traceinit"

/*
 * no implmenentation here.  This file exists to placate go vet, and friends, since
 * the directory contains no non-android files
 */
func init() {
	traceinit.TraceFunction(`\DataDog\datadog-agent\pkg\util\androidasset\notandroid.go 15`)

}