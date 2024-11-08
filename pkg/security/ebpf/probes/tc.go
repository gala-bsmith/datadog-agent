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
	"github.com/cloudflare/cbpfc"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/hashicorp/go-multierror"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/DataDog/datadog-agent/pkg/security/secl/compiler/eval"
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

const (
	// First raw packet tc program to be called
	RawPacketFilterEntryProg = "raw_packet_entry_prog"

	// RawPacketCaptureSize see kernel definition
	RawPacketCaptureSize = 256
)

// RawPacketProgOpts defines options
type RawPacketProgOpts struct {
	*cbpfc.EBPFOpts
	sendEventLabel string
}

// DefaultRawPacketProgOpts default options
var DefaultRawPacketProgOpts = RawPacketProgOpts{
	EBPFOpts: &cbpfc.EBPFOpts{
		PacketStart: asm.R1,
		PacketEnd:   asm.R2,
		Result:      asm.R3,
		Working: [4]asm.Register{
			asm.R4,
			asm.R5,
			asm.R6,
			asm.R7,
		},
		StackOffset: 16, // adapt using the stack size used outside of the filter itself, ex: map_lookup
	},
	sendEventLabel: "send-event",
}

// BPFFilterToInsts compile a bpf filter expression
func BPFFilterToInsts(index int, filter string, opts RawPacketProgOpts) (asm.Instructions, error) {
	pcapBPF, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, 256, filter)
	if err != nil {
		return nil, err
	}
	bpfInsts := make([]bpf.Instruction, len(pcapBPF))
	for i, ri := range pcapBPF {
		bpfInsts[i] = bpf.RawInstruction{Op: ri.Code, Jt: ri.Jt, Jf: ri.Jf, K: ri.K}.Disassemble()
	}

	var cbpfcOpts cbpfc.EBPFOpts
	if opts.EBPFOpts != nil {
		// make a copy so that we can modify the labels
		cbpfcOpts = *opts.EBPFOpts
	}
	cbpfcOpts.LabelPrefix = fmt.Sprintf("cbpfc-%d-", index)
	cbpfcOpts.ResultLabel = fmt.Sprintf("check-result-%d", index)

	insts, err := cbpfc.ToEBPF(bpfInsts, cbpfcOpts)
	if err != nil {
		return nil, err
	}

	// filter output
	insts = append(insts,
		asm.JNE.Imm(cbpfcOpts.Result, 0, opts.sendEventLabel).WithSymbol(cbpfcOpts.ResultLabel),
	)

	return insts, nil
}

func rawPacketFiltersToInsts(rawPacketfilters []RawPacketFilter, opts RawPacketProgOpts) (asm.Instructions, *multierror.Error) {
	var (
		insts asm.Instructions
		mErr  *multierror.Error
	)

	for i, rawPacketfilter := range rawPacketfilters {
		filterInsts, err := BPFFilterToInsts(i, rawPacketfilter.BPFFilter, opts)
		if err != nil {
			mErr = multierror.Append(mErr, fmt.Errorf("unable to generate eBPF bitcode for rule `%s`: %s", rawPacketfilter.RuleID, err))
			continue
		}
		insts = append(insts, filterInsts...)
	}

	return insts, mErr
}

// RawPacketFilter defines a raw packet filter
type RawPacketFilter struct {
	RuleID    eval.RuleID
	BPFFilter string
}

// GetRawPacketTCFilterCollectionSpec returns a first tc filter
func GetRawPacketTCFilterCollectionSpec(rawPacketEventMapFd, clsRouterMapFd int, rawpPacketFilters []RawPacketFilter) (*ebpf.CollectionSpec, error) {
	var mErr *multierror.Error

	const (
		ctxReg = asm.R9

		// raw packet data, see kernel definition
		dataSize   = 256
		dataOffset = 164
	)

	opts := DefaultRawPacketProgOpts

	// save ctx
	insts := asm.Instructions{
		asm.Mov.Reg(ctxReg, asm.R1),
	}

	// load raw event
	insts = append(insts,
		// load raw event
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4),
		asm.StoreImm(asm.R2, 0, 0, asm.Word), // index 0
		asm.LoadMapPtr(asm.R1, rawPacketEventMapFd),
		asm.FnMapLookupElem.Call(),
		asm.JNE.Imm(asm.R0, 0, "raw-packet-event-not-null"),
		asm.Return(),
	)

	// place in result in the start register and end register
	insts = append(insts,
		asm.Mov.Reg(opts.PacketStart, asm.R0).WithSymbol("raw-packet-event-not-null"),
		asm.Add.Imm(opts.PacketStart, dataOffset),
		asm.Mov.Reg(opts.PacketEnd, opts.PacketStart),
		asm.Add.Imm(opts.PacketEnd, dataSize),
	)

	// compile and convert
	filterInsts, err := rawPacketFiltersToInsts(rawpPacketFilters, DefaultRawPacketProgOpts)
	if err.ErrorOrNil() != nil {
		mErr = multierror.Append(mErr, err)
	}
	insts = append(insts, filterInsts...)

	// none of the filter matched
	insts = append(insts,
		asm.Return(),
	)

	// tail call to the send event program
	insts = append(insts,
		asm.Mov.Reg(asm.R1, ctxReg).WithSymbol(opts.sendEventLabel),
		asm.LoadMapPtr(asm.R2, clsRouterMapFd),
		asm.Mov.Imm(asm.R3, int32(TCRawPacketParserKey)),
		asm.FnTailCall.Call(),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	)

	colSpec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			RawPacketFilterEntryProg: {
				Type:         ebpf.SchedCLS,
				Instructions: insts,
				License:      "GPL",
			},
		},
	}

	return colSpec, mErr.ErrorOrNil()
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
