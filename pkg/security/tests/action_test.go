// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux && functionaltests

// Package tests holds tests related files
package tests

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/avast/retry-go/v4"
	"github.com/oliveagle/jsonpath"
	"github.com/stretchr/testify/assert"
	"go.uber.org/atomic"

	"github.com/DataDog/datadog-agent/pkg/config/env"
	"github.com/DataDog/datadog-agent/pkg/security/ebpf/kernel"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/security/secl/rules"
)

func TestActionKill(t *testing.T) {
	SkipIfNotAvailable(t)

	if !ebpfLessEnabled {
		checkKernelCompatibility(t, "bpf_send_signal is not supported on this kernel and agent is running in container mode", func(kv *kernel.Version) bool {
			return !kv.SupportBPFSendSignal() && env.IsContainerized()
		})
	}

	ruleDefs := []*rules.RuleDefinition{
		{
			ID:         "kill_action_usr2",
			Expression: `process.file.name == "syscall_tester" && open.file.path == "{{.Root}}/test-kill-action-usr2"`,
			Actions: []*rules.ActionDefinition{
				{
					Kill: &rules.KillDefinition{
						Signal: "SIGUSR2",
					},
				},
			},
		},
		{
			ID:         "kill_action_kill",
			Expression: `process.file.name == "syscall_tester" && open.file.path == "{{.Root}}/test-kill-action-kill"`,
			Actions: []*rules.ActionDefinition{
				{
					Kill: &rules.KillDefinition{
						Signal: "SIGKILL",
					},
				},
			},
		},
	}

	test, err := newTestModule(t, nil, ruleDefs)
	if err != nil {
		t.Fatal(err)
	}
	defer test.Close()

	syscallTester, err := loadSyscallTester(t, test, "syscall_tester")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("kill-action-usr2", func(t *testing.T) {
		testFile, _, err := test.Path("test-kill-action-usr2")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(testFile)

		err = test.GetEventSent(t, func() error {
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGUSR1)
			defer signal.Stop(sigCh)

			timeoutCtx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
			defer cancel()

			if err := runSyscallTesterFunc(
				timeoutCtx, t, syscallTester,
				"set-signal-handler", ";",
				"open", testFile, ";",
				"sleep", "1", ";",
				"open", testFile, ";",
				"wait-signal", ";",
				"signal", "sigusr1", strconv.Itoa(int(os.Getpid())), ";",
				"sleep", "1",
			); err != nil {
				t.Error(err)
			}

			select {
			case <-sigCh:
			case <-time.After(time.Second * 3):
				t.Error("signal timeout")
			}
			return nil
		}, func(rule *rules.Rule, event *model.Event) bool {
			return true
		}, time.Second*3, "kill_action_usr2")
		if err != nil {
			t.Error(err)
		}

		err = retry.Do(func() error {
			msg := test.msgSender.getMsg("kill_action_usr2")
			if msg == nil {
				return errors.New("not found")
			}
			validateMessageSchema(t, string(msg.Data))

			jsonPathValidation(test, msg.Data, func(testMod *testModule, obj interface{}) {
				if _, err := jsonpath.JsonPathLookup(obj, `$.agent.rule_actions[?(@.signal="sigusr2")]`); err != nil {
					t.Error(err)
				}
			})

			return nil
		}, retry.Delay(200*time.Millisecond), retry.Attempts(30), retry.DelayType(retry.FixedDelay))
		assert.NoError(t, err)
	})

	t.Run("kill-action-kill", func(t *testing.T) {
		testFile, _, err := test.Path("test-kill-action-kill")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(testFile)

		err = test.GetEventSent(t, func() error {
			ch := make(chan bool, 1)

			go func() {
				timeoutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				cmd := exec.CommandContext(timeoutCtx, syscallTester, "open", testFile, ";", "sleep", "1", ";", "open", testFile, ";", "sleep", "5")
				_ = cmd.Run()

				ch <- true
			}()

			select {
			case <-ch:
			case <-time.After(time.Second * 3):
				t.Error("signal timeout")
			}
			return nil
		}, func(rule *rules.Rule, event *model.Event) bool {
			return true
		}, time.Second*5, "kill_action_kill")

		if err != nil {
			t.Error(err)
		}

		err = retry.Do(func() error {
			msg := test.msgSender.getMsg("kill_action_kill")
			if msg == nil {
				return errors.New("not found")
			}
			validateMessageSchema(t, string(msg.Data))

			jsonPathValidation(test, msg.Data, func(testMod *testModule, obj interface{}) {
				if _, err := jsonpath.JsonPathLookup(obj, `$.agent.rule_actions[?(@.signal="sigkill")]`); err != nil {
					t.Error(err)
				}
				if _, err = jsonpath.JsonPathLookup(obj, `$.agent.rule_actions[?(@.exited_at=~/20.*/)]`); err != nil {
					t.Error(err)
				}
			})

			return nil
		}, retry.Delay(200*time.Millisecond), retry.Attempts(30), retry.DelayType(retry.FixedDelay))
		assert.NoError(t, err)
	})
}

func TestActionKillExcludeBinary(t *testing.T) {
	SkipIfNotAvailable(t)

	checkKernelCompatibility(t, "bpf_send_signal is not supported on this kernel and agent is running in container mode", func(kv *kernel.Version) bool {
		return !kv.SupportBPFSendSignal() && env.IsContainerized()
	})

	ruleDefs := []*rules.RuleDefinition{
		{
			ID:         "kill_action_kill_exclude",
			Expression: `exec.file.name == "sleep" && exec.argv in ["1234567"]`,
			Actions: []*rules.ActionDefinition{
				{
					Kill: &rules.KillDefinition{
						Signal: "SIGKILL",
					},
				},
			},
		},
	}

	executable := which(t, "sleep")

	test, err := newTestModule(t, nil, ruleDefs, withStaticOpts(testOpts{enforcementExcludeBinary: executable}))
	if err != nil {
		t.Fatal(err)
	}
	defer test.Close()

	killed := atomic.NewBool(false)

	err = test.GetEventSent(t, func() error {
		go func() {
			timeoutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			cmd := exec.CommandContext(timeoutCtx, "sleep", "1234567")
			_ = cmd.Run()

			killed.Store(true)
		}()

		return nil
	}, func(rule *rules.Rule, event *model.Event) bool {
		return true
	}, time.Second*5, "kill_action_kill_exclude")

	if err != nil {
		t.Error("should get an event")
	}

	if killed.Load() {
		t.Error("shouldn't be killed")
	}
}

func TestActionKillRuleSpecific(t *testing.T) {
	SkipIfNotAvailable(t)

	if !ebpfLessEnabled {
		checkKernelCompatibility(t, "bpf_send_signal is not supported on this kernel and agent is running in container mode", func(kv *kernel.Version) bool {
			return !kv.SupportBPFSendSignal() && env.IsContainerized()
		})
	}

	ruleDefs := []*rules.RuleDefinition{
		{
			ID:         "kill_action_kill",
			Expression: `process.file.name == "syscall_tester" && open.file.path == "{{.Root}}/test-kill-action-kill"`,
			Actions: []*rules.ActionDefinition{
				{
					Kill: &rules.KillDefinition{
						Signal: "SIGKILL",
					},
				},
			},
		},
		{
			ID:         "kill_action_no_kill",
			Expression: `process.file.name == "syscall_tester" && open.file.path == "{{.Root}}/test-kill-action-kill"`,
		},
	}

	test, err := newTestModule(t, nil, ruleDefs)
	if err != nil {
		t.Fatal(err)
	}
	defer test.Close()

	syscallTester, err := loadSyscallTester(t, test, "syscall_tester")
	if err != nil {
		t.Fatal(err)
	}

	testFile, _, err := test.Path("test-kill-action-kill")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(testFile)

	err = test.GetEventSent(t, func() error {
		ch := make(chan bool, 1)

		go func() {
			timeoutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			cmd := exec.CommandContext(timeoutCtx, syscallTester, "open", testFile, ";", "sleep", "1", ";", "open", testFile, ";", "sleep", "5")
			_ = cmd.Run()

			ch <- true
		}()

		select {
		case <-ch:
		case <-time.After(time.Second * 3):
			t.Error("signal timeout")
		}
		return nil
	}, func(rule *rules.Rule, event *model.Event) bool {
		return true
	}, time.Second*5, "kill_action_kill")

	if err != nil {
		t.Error(err)
	}

	err = retry.Do(func() error {
		msg := test.msgSender.getMsg("kill_action_kill")
		if msg == nil {
			return errors.New("not found")
		}
		validateMessageSchema(t, string(msg.Data))

		jsonPathValidation(test, msg.Data, func(testMod *testModule, obj interface{}) {
			if _, err := jsonpath.JsonPathLookup(obj, `$.agent.rule_actions[?(@.signal="sigkill")]`); err != nil {
				t.Error(err)
			}
			if _, err = jsonpath.JsonPathLookup(obj, `$.agent.rule_actions[?(@.exited_at=~/20.*/)]`); err != nil {
				t.Error(err)
			}
		})

		return nil
	}, retry.Delay(200*time.Millisecond), retry.Attempts(30), retry.DelayType(retry.FixedDelay))
	assert.NoError(t, err)

	err = retry.Do(func() error {
		msg := test.msgSender.getMsg("kill_action_no_kill")
		if msg == nil {
			return errors.New("not found")
		}
		validateMessageSchema(t, string(msg.Data))

		jsonPathValidation(test, msg.Data, func(testMod *testModule, obj interface{}) {
			if _, err := jsonpath.JsonPathLookup(obj, `$.agent.rule_actions`); err == nil {
				t.Error(errors.New("unexpected rule action"))
			}
		})

		return nil
	}, retry.Delay(200*time.Millisecond), retry.Attempts(30), retry.DelayType(retry.FixedDelay))
	assert.NoError(t, err)
}
