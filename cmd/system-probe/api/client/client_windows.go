// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build windows

package client

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/Microsoft/go-winio"

	"github.com/DataDog/datadog-agent/pkg/util/log"
)

const (
	idleConnTimeout = 5 * time.Second
)

func DialContextFunc(pipeName string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Go clients do not immediately close (named pipe) connections when done,
		// they keep connections idle for a while.  Make sure the idle time
		// is not too high and the timeout is generous enough for pending connections.
		var timeout = time.Duration(30 * time.Second)

		namedPipe, err := winio.DialPipe(pipeName, &timeout)
		if err != nil {
			// This important error may not get reported upstream, making connection failures
			// very difficult to diagnose. Explicitly log the error here too for diagnostics.
			var namedPipeErr = fmt.Errorf("error connecting to named pipe %s : %s", pipeName, err)
			log.Errorf("%s", namedPipeErr.Error())
			return nil, namedPipeErr
		}

		return namedPipe, nil
	}
}
