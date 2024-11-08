// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package holds JSON schemas validation code
package schemas

import (
	"embed"
)

//nolint:deadcode,unused
//go:embed *.schema.json
var AssetFS embed.FS
