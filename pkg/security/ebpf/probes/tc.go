// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

// Package probes holds probes related files
package probes

import (
	"fmt"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"golang.org/x/sys/unix"
)

// GetTCProbes returns the list of TCProbes
func GetTCProbes(withNetworkIngress bool) []*manager.Probe {
	out := []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          SecurityAgentUID,
				EBPFFuncName: "classifier_egress",
			},
			NetworkDirection: manager.Egress,
			TCFilterProtocol: unix.ETH_P_ALL,
			KeepProgramSpec:  true,
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          SecurityAgentUID,
				EBPFFuncName: "classifier_raw_packet_egress",
			},
			NetworkDirection: manager.Egress,
			TCFilterProtocol: unix.ETH_P_ALL,
			KeepProgramSpec:  true,
		},
	}

	if withNetworkIngress {
		out = append(out, &manager.Probe{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          SecurityAgentUID,
				EBPFFuncName: "classifier_ingress",
			},
			NetworkDirection: manager.Ingress,
			TCFilterProtocol: unix.ETH_P_ALL,
			KeepProgramSpec:  true,
		})
		out = append(out, &manager.Probe{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          SecurityAgentUID,
				EBPFFuncName: "classifier_raw_packet_ingress",
			},
			NetworkDirection: manager.Ingress,
			TCFilterProtocol: unix.ETH_P_ALL,
			KeepProgramSpec:  true,
		})
	}

	return out
}

// RawPacketTCProgram returns the list of TC classifier sections
var RawPacketTCProgram = []string{
	"classifier_raw_packet_egress",
	"classifier_raw_packet_ingress",
}

// GetRawPacketTCFilterProg returns a first tc filter
func GetRawPacketTCFilterProg(rawPacketEventMapFd, clsRouterMapFd int) (*ebpf.ProgramSpec, error) {
	const (
		ctxReg  = asm.R9
		dataReg = asm.R6
	)

	insts := asm.Instructions{
		// save ctx
		asm.Mov.Reg(ctxReg, asm.R1),

		// load raw event
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4),
		asm.StoreImm(asm.R2, 0, 0, asm.Word),
		asm.LoadMapPtr(asm.R1, rawPacketEventMapFd),
		asm.FnMapLookupElem.Call(),
		asm.JNE.Imm(asm.R0, 0, "raw-packet-event-not-null"),
		asm.Return(),
		asm.Mov.Reg(dataReg, asm.R0).WithSymbol("raw-packet-event-not-null"),

		// jump to the send event program
		asm.Mov.Reg(asm.R1, ctxReg),
		asm.LoadMapPtr(asm.R2, clsRouterMapFd),
		asm.Mov.Imm(asm.R3, int32(TCRawPacketParserKey)),
		asm.FnTailCall.Call(),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	}

	fmt.Printf("INS: %+v\n", insts)

	return &ebpf.ProgramSpec{
		Type:         ebpf.SchedCLS,
		Instructions: insts,
		License:      "GPL",
	}, nil
}

// GetAllTCProgramFunctions returns the list of TC classifier sections
func GetAllTCProgramFunctions() []string {
	output := []string{
		"classifier_dns_request_parser",
		"classifier_dns_request",
		"classifier_imds_request",
		"classifier_raw_packet",
	}

	for _, tcProbe := range GetTCProbes(true) {
		output = append(output, tcProbe.EBPFFuncName)
	}

	for _, flowProbe := range getFlowProbes() {
		output = append(output, flowProbe.EBPFFuncName)
	}

	for _, netDeviceProbe := range getNetDeviceProbes() {
		output = append(output, netDeviceProbe.EBPFFuncName)
	}

	return output
}

func getTCTailCallRoutes() []manager.TailCallRoute {
	return []manager.TailCallRoute{
		{
			ProgArrayName: "classifier_router",
			Key:           TCDNSRequestKey,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "classifier_dns_request",
			},
		},
		{
			ProgArrayName: "classifier_router",
			Key:           TCDNSRequestParserKey,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "classifier_dns_request_parser",
			},
		},
		{
			ProgArrayName: "classifier_router",
			Key:           TCIMDSRequestParserKey,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "classifier_imds_request",
			},
		},
		{
			ProgArrayName: "classifier_router",
			Key:           TCRawPacketParserKey,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "classifier_raw_packet",
			},
		},
	}
}
