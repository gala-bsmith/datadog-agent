// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package util

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	pkgconfigsetup "github.com/DataDog/datadog-agent/pkg/config/setup"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// AddrResolver is a map that provides, for a given Agent domain name, a function to retrieve its real transport address (e.g., "core-cmd" -> "127.0.0.1:5001").
// The function can return either the address or an error.
type AddrResolver map[string]func() (net.Addr, error)

// The following constant values represent the Agent domain names
const (
	CoreCmd        = "core-cmd"        // CoreCmd is the core Agent command endpoint
	CoreIPC        = "core-ipc"        // CoreIPC is the core Agent configuration synchronisation endpoint
	CoreExpvar     = "core-expvar"     // CoreExpvar is the core Agent expvar endpoint
	TraceCmd       = "trace-cmd"       // TraceCmd is the trace Agent command endpoint
	TraceExpvar    = "trace-expvar"    // TraceExpvar is the trace Agent expvar endpoint
	SecurityCmd    = "security-cmd"    // SecurityCmd is the security Agent command endpoint
	SecurityExpvar = "security-expvar" // SecurityExpvar is the security Agent expvar endpoint
	ProcessCmd     = "process-agent"   // ProcessCmd is the process Agent command endpoint
	ProcessExpvar  = "process-expvar"  // ProcessExpvar is the process Agent expvar endpoint
	ClusterAgent   = "cluster-agent"   // ClusterAgent is the Cluster Agent command endpoint
)

type dialContext func(ctx context.Context, network string, addr string) (net.Conn, error)

var db = AddrResolver{
	CoreCmd: func() (net.Addr, error) {
		config := pkgconfigsetup.Datadog()
		// host, err := pkgconfigsetup.GetIPCAddress(config)

		// if err != nil {
		// 	return nil, err

		// }
		return net.ResolveUnixAddr("unix", filepath.Join(filepath.Dir(config.ConfigFileUsed()), CoreCmd+".sock"))
	},
	CoreIPC: func() (net.Addr, error) {
		config := pkgconfigsetup.Datadog()
		port := config.GetInt("agent_ipc.port")
		if port <= 0 {
			return nil, fmt.Errorf("agent_ipc.port cannot be <= 0")
		}

		return net.ResolveTCPAddr("tcp", net.JoinHostPort(config.GetString("agent_ipc.host"), strconv.Itoa(port)))
	},
	CoreExpvar: func() (net.Addr, error) {
		config := pkgconfigsetup.Datadog()
		host, err := pkgconfigsetup.GetIPCAddress(config)

		if err != nil {
			return nil, err
		}
		return net.ResolveTCPAddr("tcp", net.JoinHostPort(host, config.GetString("expvar_port")))
	},

	TraceCmd: func() (net.Addr, error) {
		config := pkgconfigsetup.Datadog()
		host, err := pkgconfigsetup.GetIPCAddress(config)

		if err != nil {
			return nil, err
		}
		return net.ResolveTCPAddr("tcp", net.JoinHostPort(host, config.GetString("apm_config.debug.port")))
	},
	TraceExpvar: func() (net.Addr, error) {
		config := pkgconfigsetup.Datadog()
		host, err := pkgconfigsetup.GetIPCAddress(config)

		if err != nil {
			return nil, err
		}
		return net.ResolveTCPAddr("tcp", net.JoinHostPort(host, config.GetString("apm_config.debug.port")))
	},

	ProcessCmd: func() (net.Addr, error) {
		addr, err := pkgconfigsetup.GetProcessAPIAddressPort(pkgconfigsetup.Datadog())
		if err != nil {
			return nil, err
		}
		return net.ResolveTCPAddr("tcp", addr)
	},
	ProcessExpvar: func() (net.Addr, error) {
		config := pkgconfigsetup.Datadog()
		host, err := pkgconfigsetup.GetIPCAddress(config)

		if err != nil {
			return nil, err
		}
		return net.ResolveTCPAddr("tcp", net.JoinHostPort(host, config.GetString("process_config.expvar_port")))
	},

	SecurityCmd: func() (net.Addr, error) {
		addr, err := pkgconfigsetup.GetSecurityAgentAPIAddressPort(pkgconfigsetup.Datadog())
		if err != nil {
			return nil, err
		}

		return net.ResolveTCPAddr("tcp", addr)
	},
	SecurityExpvar: func() (net.Addr, error) {
		config := pkgconfigsetup.Datadog()
		host, err := pkgconfigsetup.GetIPCAddress(config)

		if err != nil {
			return nil, err
		}
		return net.ResolveTCPAddr("tcp", net.JoinHostPort(host, config.GetString("security_agent.expvar_port")))
	},

	ClusterAgent: func() (net.Addr, error) {
		config := pkgconfigsetup.Datadog()
		host, err := pkgconfigsetup.GetIPCAddress(config)

		if err != nil {
			return nil, err
		}
		return net.ResolveTCPAddr("tcp", net.JoinHostPort(host, config.GetString("cluster_agent.cmd_port")))
	},
}

// ClientOption allows configuration of the *http.Client during construction
type ClientOption func(*http.Client)

// GetClient returns a ClientBuilder struct that lets you create an Agent-specific client.
// To get an [*net/http.Client] object from the return value, call the Build() function.
// To provide specific features to your client, call the related With...() functions.
//
// Note: The order in which the With functions are called does not affect the final configuration
//
// # Example usage
//
//	client := GetClient().WithNoVerify().WithResolver().Build()
//
// This example creates an HTTP client with no TLS verification and a custom resolver.
func GetClient(options ...ClientOption) *http.Client {
	client := http.Client{
		Transport: &http.Transport{
			DialContext: newDialContext(),
		},
	}

	for _, opt := range options {
		opt(&client)
	}

	return &client
}

// WithNoVerify configures the client to skip TLS verification.
//
// Example usage:
//
// # Example usage
//
//	client := GetClient().WithNoVerify().Build()
//
// This example creates an HTTP client that skips TLS verification.
func WithNoVerify() func(c *http.Client) {
	return func(c *http.Client) {
		if tr, ok := c.Transport.(*http.Transport); ok {
			tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		} else {
			log.Warn("unable to update Client transport: transport is not of type http.Transport")
		}
	}
}

// WithTimeout sets the timeout for the HTTP client.
//
// # Example usage
//
//	client := GetClient().WithTimeout(30 * time.Second).Build()
//
// This example creates an HTTP client with a 30-second timeout.
func WithTimeout(to time.Duration) func(c *http.Client) {
	return func(c *http.Client) {
		c.Timeout = to
	}
}
