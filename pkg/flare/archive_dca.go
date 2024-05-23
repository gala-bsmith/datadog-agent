// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package flare

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"

	flarehelpers "github.com/DataDog/datadog-agent/comp/core/flare/helpers"
	flaretypes "github.com/DataDog/datadog-agent/comp/core/flare/types"
	"github.com/DataDog/datadog-agent/comp/core/status"
	apiv1 "github.com/DataDog/datadog-agent/pkg/clusteragent/api/v1"
	"github.com/DataDog/datadog-agent/pkg/clusteragent/autoscaling/custommetrics"
	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/status/render"
	"github.com/DataDog/datadog-agent/pkg/util/kubernetes/apiserver"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// ProfileData maps (pprof) profile names to the profile data
type ProfileData map[string][]byte

// CreateDCAArchive packages up the files
func CreateDCAArchive(local bool, distPath, logFilePath string, pdata ProfileData, statusComponent status.Component) (string, error) {
	fb, err := flarehelpers.NewFlareBuilder(local)
	if err != nil {
		return "", err
	}

	confSearchPaths := map[string]string{
		"":     config.Datadog.GetString("confd_path"),
		"dist": filepath.Join(distPath, "conf.d"),
	}

	createDCAArchive(fb, confSearchPaths, logFilePath, pdata, statusComponent)
	return fb.Save()
}

func createDCAArchive(fb flaretypes.FlareBuilder, confSearchPaths map[string]string, logFilePath string, pdata ProfileData, statusComponent status.Component) {
	// If the request against the API does not go through we don't collect the status log.
	if fb.IsLocal() {
		fb.AddFile("local", nil) //nolint:errcheck
	} else {
		// The Status will be unavailable unless the agent is running.
		// Only zip it up if the agent is running
		err := fb.AddFileFromFunc("cluster-agent-status.log", func() ([]byte, error) { return statusComponent.GetStatus("text", true) }) //nolint:errcheck
		if err != nil {
			log.Errorf("Error getting the status of the DCA, %q", err)
			return
		}

	}

	getLogFiles(fb, logFilePath)
	getConfigFiles(fb, confSearchPaths)
	getClusterAgentConfigCheck(fb)                                                 //nolint:errcheck
	getExpVar(fb)                                                                  //nolint:errcheck
	getMetadataMap(fb)                                                             //nolint:errcheck
	getClusterAgentClusterChecks(fb)                                               //nolint:errcheck
	getClusterAgentDiagnose(fb)                                                    //nolint:errcheck
	fb.AddFileFromFunc("agent-daemonset.yaml", getAgentDaemonSet)                  //nolint:errcheck
	fb.AddFileFromFunc("cluster-agent-deployment.yaml", getClusterAgentDeployment) //nolint:errcheck
	fb.AddFileFromFunc("helm-values.yaml", getHelmValues)                          //nolint:errcheck
	fb.AddFileFromFunc("envvars.log", getEnvVars)                                  //nolint:errcheck
	fb.AddFileFromFunc("telemetry.log", QueryDCAMetrics)                           //nolint:errcheck
	fb.AddFileFromFunc("tagger-list.json", getDCATaggerList)                       //nolint:errcheck
	fb.AddFileFromFunc("workload-list.log", getDCAWorkloadList)                    //nolint:errcheck
	getPerformanceProfileDCA(fb, pdata)

	if config.Datadog.GetBool("external_metrics_provider.enabled") {
		getHPAStatus(fb) //nolint:errcheck
	}
}

// QueryDCAMetrics gets the metrics payload exposed by the cluster agent
func QueryDCAMetrics() ([]byte, error) {
	r, err := http.Get(fmt.Sprintf("http://localhost:%d/metrics", config.Datadog.GetInt("metrics_port")))
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	return io.ReadAll(r.Body)
}

func getMetadataMap(fb flaretypes.FlareBuilder) error {
	metaList := apiv1.NewMetadataResponse()
	cl, err := apiserver.GetAPIClient()
	if err != nil {
		metaList.Errors = fmt.Sprintf("Can't create client to query the API Server: %s", err.Error())
	} else {
		// Grab the metadata map for all nodes.
		metaList, err = apiserver.GetMetadataMapBundleOnAllNodes(cl)
		if err != nil {
			log.Infof("Error while collecting the cluster level metadata: %q", err)
		}
	}

	metaBytes, err := json.Marshal(metaList)
	if err != nil {
		return log.Errorf("Error while marshalling the cluster level metadata: %q", err)
	}

	str, err := render.FormatMetadataMapCLI(metaBytes)
	if err != nil {
		return log.Errorf("Error while rendering the cluster level metadata: %q", err)
	}

	return fb.AddFile("cluster-agent-metadatamapper.log", []byte(str))
}

func getClusterAgentClusterChecks(fb flaretypes.FlareBuilder) error {
	var b bytes.Buffer

	writer := bufio.NewWriter(&b)
	GetClusterChecks(writer, "") //nolint:errcheck
	writer.Flush()

	return fb.AddFile("clusterchecks.log", b.Bytes())
}

func getHPAStatus(fb flaretypes.FlareBuilder) error {
	stats := make(map[string]interface{})
	apiCl, err := apiserver.GetAPIClient()
	if err != nil {
		stats["custommetrics"] = map[string]string{"Error": err.Error()}
	} else {
		stats["custommetrics"] = custommetrics.GetStatus(apiCl.Cl)
	}
	statsBytes, err := json.Marshal(stats)
	if err != nil {
		return log.Errorf("Error while marshalling the cluster level metadata: %q", err)
	}

	str, err := render.FormatHPAStatus(statsBytes)
	if err != nil {
		return log.Errorf("Could not collect custommetricsprovider.log: %s", err)
	}

	return fb.AddFile("custommetricsprovider.log", []byte(str))
}

func getClusterAgentConfigCheck(fb flaretypes.FlareBuilder) error {
	var b bytes.Buffer

	writer := bufio.NewWriter(&b)
	GetClusterAgentConfigCheck(writer, true) //nolint:errcheck
	writer.Flush()

	return fb.AddFile("config-check.log", b.Bytes())
}

func getClusterAgentDiagnose(fb flaretypes.FlareBuilder) error {
	var b bytes.Buffer

	writer := bufio.NewWriter(&b)
	GetClusterAgentDiagnose(writer) //nolint:errcheck
	writer.Flush()

	return fb.AddFile("diagnose.log", b.Bytes())
}

func getDCATaggerList() ([]byte, error) {
	ipcAddress, err := config.GetIPCAddress()
	if err != nil {
		return nil, err
	}

	taggerListURL := fmt.Sprintf("https://%v:%v/tagger-list", ipcAddress, config.Datadog.GetInt("cluster_agent.cmd_port"))

	return getTaggerList(taggerListURL)
}

func getDCAWorkloadList() ([]byte, error) {
	ipcAddress, err := config.GetIPCAddress()
	if err != nil {
		return nil, err
	}

	return getWorkloadList(fmt.Sprintf("https://%v:%v/workload-list?verbose=true", ipcAddress, config.Datadog.GetInt("cluster_agent.cmd_port")))
}

func getPerformanceProfileDCA(fb flaretypes.FlareBuilder, pdata ProfileData) {
	for name, data := range pdata {
		fb.AddFileWithoutScrubbing(filepath.Join("profiles", name), data) //nolint:errcheck
	}
}
