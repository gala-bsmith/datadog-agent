// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !windows

package util

import (
	"context"
	"fmt"
	"net"
)

// func getDialContext(config config.Reader) DialContext {
func getDialContext() dialContext {
	return func(_ context.Context, network string, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		if resolver, ok := db[host]; ok {
			path, err := resolver()

			if err != nil {
				return nil, err
			}

			fmt.Printf("receive request for %v, reaching %v", host, path)

			return net.Dial("tcp", path)
		}
		return nil, fmt.Errorf("%v: unknown Agent address", host)
	}
}
