// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !windows

package apm

import (
	"os"
	"strings"
	"testing"
)

func Test_javaDetector(t *testing.T) {
	data := []struct {
		name   string
		args   []string
		envs   map[string]string
		result Instrumentation
	}{
		{
			name:   "not there",
			args:   strings.Split("java -jar Foo.jar Foo", " "),
			result: None,
		},
		{
			name:   "version",
			args:   strings.Split("java -version", " "),
			result: None,
		},
	}
	for _, d := range data {
		t.Run(d.name, func(t *testing.T) {
			result := javaDetector(d.args, d.envs)
			if result != d.result {
				t.Errorf("expected %s got %s", d.result, result)
			}
		})
	}
}

func Test_pythonDetector(t *testing.T) {
	tmpDir := t.TempDir()
	err := os.MkdirAll(tmpDir+"/lib/python3.11/site-packages/ddtrace", 0700)
	if err != nil {
		t.Fatal(err)
	}
	tmpDir2 := t.TempDir()
	err = os.MkdirAll(tmpDir2+"/lib/python3.11/site-packages/notddtrace", 0700)
	if err != nil {
		t.Fatal(err)
	}
	data := []struct {
		name   string
		args   []string
		envs   map[string]string
		result Instrumentation
	}{
		{
			name:   "venv_provided",
			args:   []string{"./echoer.sh", "nope"},
			envs:   map[string]string{"VIRTUAL_ENV": tmpDir},
			result: Provided,
		},
		{
			name:   "venv_none",
			args:   []string{"./testdata/echoer.sh", "nope"},
			envs:   map[string]string{"VIRTUAL_ENV": tmpDir2},
			result: None,
		},
		{
			name:   "cmd_provided",
			args:   []string{"./testdata/cmd_works.sh"},
			result: Provided,
		},
		{
			name:   "cmd_none",
			args:   []string{"./testdata/cmd_fails.sh"},
			result: None,
		},
	}
	for _, d := range data {
		t.Run(d.name, func(t *testing.T) {
			result := pythonDetector(d.args, d.envs)
			if result != d.result {
				t.Errorf("expected %s got %s", d.result, result)
			}
		})
	}
}
