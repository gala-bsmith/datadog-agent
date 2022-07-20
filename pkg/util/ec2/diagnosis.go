// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package ec2

import (
	"context"

	"github.com/DataDog/datadog-agent/pkg/diagnose/diagnosis"
)
import "github.com/DataDog/datadog-agent/pkg/traceinit"


func init() {
	traceinit.TraceFunction(`\DataDog\datadog-agent\pkg\util\ec2\diagnosis.go 14`)
	diagnosis.Register("EC2 Metadata availability", diagnose)
	traceinit.TraceFunction(`\DataDog\datadog-agent\pkg\util\ec2\diagnosis.go 15`)
}

// diagnose the ec2 metadata API availability
func diagnose() error {
	_, err := GetHostname(context.TODO())
	return err
}