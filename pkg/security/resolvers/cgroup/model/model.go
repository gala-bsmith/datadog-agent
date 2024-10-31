// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

// Package model holds model related files
package model

import (
	"errors"
	"fmt"
	"sync"

	"go.uber.org/atomic"

	"github.com/DataDog/datadog-agent/pkg/security/secl/containerutils"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/security/utils"
)

var (
	ErrNoImageProvided       = errors.New("no image name provided")  // ErrNoImageProvided is returned when no image name is provided
	ErrNoContainerIDProvided = errors.New("no containerID provided") // ErrNoContainerIDProvided is returned when no containerID is provided
)

// WorkloadSelector is a selector used to uniquely indentify the image of a workload
type WorkloadSelector struct {
	Image       string
	Tag         string
	ContainerID string
}

// NewSelector returns an initialized instance of a WorkloadSelector
func NewSelector(image string, tag string, containerID string) (WorkloadSelector, error) {
	if image == "" {
		return WorkloadSelector{}, ErrNoImageProvided
	} else if containerID == "" {
		return WorkloadSelector{}, ErrNoContainerIDProvided
	} else if tag == "" {
		tag = "latest"
	}
	return WorkloadSelector{
		Image:       image,
		Tag:         tag,
		ContainerID: containerID,
	}, nil
}

// NewWorkloadSelector returns an initialized instance of a WorkloadSelector for an image
func NewWorkloadSelector(image string, tag string) (WorkloadSelector, error) {
	return NewSelector(image, tag, "*")
}

// NewContainerSelector returns an initialized instance of a WorkloadSelector for a single container
func NewContainerSelector(containerID string) (WorkloadSelector, error) {
	return NewSelector("*", "*", containerID)
}

func NewWorkloadSelectorFromContainerContext(cc *model.ContainerContext) WorkloadSelector {
	ws := WorkloadSelector{
		Image:       utils.GetTagValue("image_name", cc.Tags),
		Tag:         utils.GetTagValue("image_tag", cc.Tags),
		ContainerID: string(cc.ContainerID),
	}
	if ws.Image == "" {
		ws.Image = "*"
	}
	if ws.Tag == "" {
		ws.Tag = "*"
	}
	return ws
}

func (ws *WorkloadSelector) Copy() *WorkloadSelector {
	return &WorkloadSelector{
		Image:       ws.Image,
		Tag:         ws.Tag,
		ContainerID: ws.ContainerID,
	}
}

// IsReady returns true if the selector is ready
func (ws *WorkloadSelector) IsReady() bool {
	return len(ws.Image) != 0
}

// Match returns true if the input selector matches the current selector
func (ws *WorkloadSelector) Match(selector WorkloadSelector) bool {
	if ws.ContainerID == "*" || selector.ContainerID == "*" {
		if ws.Tag == "*" || selector.Tag == "*" {
			return ws.Image == selector.Image
		}
		return ws.Image == selector.Image && ws.Tag == selector.Tag
	}
	return ws.Image == selector.Image && ws.Tag == selector.Tag && ws.ContainerID == selector.ContainerID
}

// String returns a string representation of a workload selector
func (ws WorkloadSelector) String() string {
	return fmt.Sprintf("[image_name:%s image_tag:%s container_id:%s]", ws.Image, ws.Tag, ws.ContainerID)
}

// ToTags returns a string array representation of a workload selector, used in profile manger to send stats
func (ws WorkloadSelector) ToTags() []string {
	return []string{
		"image_name:" + ws.Image,
		"image_tag:" + ws.Tag,
	}
}

// CacheEntry cgroup resolver cache entry
type CacheEntry struct {
	model.CGroupContext
	model.ContainerContext
	sync.RWMutex
	Deleted          *atomic.Bool
	WorkloadSelector WorkloadSelector
	PIDs             map[uint32]bool
}

// NewCacheEntry returns a new instance of a CacheEntry
func NewCacheEntry(containerID string, cgroupFlags uint64, pids ...uint32) (*CacheEntry, error) {
	newCGroup := CacheEntry{
		Deleted: atomic.NewBool(false),
		CGroupContext: model.CGroupContext{
			CGroupID:    containerutils.GetCgroupFromContainer(containerutils.ContainerID(containerID), containerutils.CGroupFlags(cgroupFlags)),
			CGroupFlags: containerutils.CGroupFlags(cgroupFlags),
		},
		ContainerContext: model.ContainerContext{
			ContainerID: containerutils.ContainerID(containerID),
		},
		PIDs: make(map[uint32]bool, 10),
	}

	for _, pid := range pids {
		newCGroup.PIDs[pid] = true
	}
	return &newCGroup, nil
}

// GetPIDs returns the list of pids for the current workload
func (cgce *CacheEntry) GetPIDs() []uint32 {
	cgce.RLock()
	defer cgce.RUnlock()

	pids := make([]uint32, len(cgce.PIDs))
	i := 0
	for k := range cgce.PIDs {
		pids[i] = k
		i++
	}

	return pids
}

// RemovePID removes the provided pid from the list of pids
func (cgce *CacheEntry) RemovePID(pid uint32) {
	cgce.Lock()
	defer cgce.Unlock()

	delete(cgce.PIDs, pid)
}

// AddPID adds a pid to the list of pids
func (cgce *CacheEntry) AddPID(pid uint32) {
	cgce.Lock()
	defer cgce.Unlock()

	cgce.PIDs[pid] = true
}

// SetTags sets the tags for the provided workload
func (cgce *CacheEntry) SetTags(tags []string) {
	cgce.Lock()
	defer cgce.Unlock()

	cgce.Tags = tags
	cgce.WorkloadSelector.Image = utils.GetTagValue("image_name", tags)
	cgce.WorkloadSelector.Tag = utils.GetTagValue("image_tag", tags)
	if len(cgce.WorkloadSelector.Image) != 0 && len(cgce.WorkloadSelector.Tag) == 0 {
		cgce.WorkloadSelector.Tag = "latest"
	}
}

// GetWorkloadSelectorCopy returns a copy of the workload selector of this cgroup
func (cgce *CacheEntry) GetWorkloadSelectorCopy() *WorkloadSelector {
	cgce.Lock()
	defer cgce.Unlock()

	return cgce.WorkloadSelector.Copy()
}

// NeedsTagsResolution returns true if this workload is missing its tags
func (cgce *CacheEntry) NeedsTagsResolution() bool {
	return len(cgce.ContainerID) != 0 && !cgce.WorkloadSelector.IsReady()
}
