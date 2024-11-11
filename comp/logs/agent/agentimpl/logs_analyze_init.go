// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !serverless

package agentimpl

import (
	"fmt"
	"time"

	configComponent "github.com/DataDog/datadog-agent/comp/core/config"
	"github.com/DataDog/datadog-agent/comp/logs/agent/config"
	"github.com/DataDog/datadog-agent/pkg/logs/launchers"
	filelauncher "github.com/DataDog/datadog-agent/pkg/logs/launchers/file"
	"github.com/DataDog/datadog-agent/pkg/logs/pipeline"
	"github.com/DataDog/datadog-agent/pkg/logs/sources"
)

func SetUpLaunchers(conf configComponent.Component) {
	processingRules, err := config.GlobalProcessingRules(conf)
	if err != nil {
		return
	}

	pipelineProvider := pipeline.NewProcessorOnlyProvider(nil, processingRules, conf, nil)

	// setup the launchers
	lnchrs := launchers.NewLaunchers(nil, pipelineProvider, nil, nil)

	fileLimits := 500
	fileValidatePodContainer := false
	fileScanPeriod := time.Duration(10.0 * float64(time.Second))
	fileWildcardSelectionMode := "by_name"
	fileLauncher := filelauncher.NewLauncher(
		fileLimits,
		filelauncher.DefaultSleepDuration,
		fileValidatePodContainer,
		fileScanPeriod,
		fileWildcardSelectionMode,
		nil,
		nil)
	sourceProvider := sources.GetInstance()
	fmt.Printf("WACK logs_analyze_init %p \n", sourceProvider)
	fileLauncher.Start(sourceProvider, pipelineProvider, nil, nil)
	lnchrs.AddLauncher(fileLauncher)
}
