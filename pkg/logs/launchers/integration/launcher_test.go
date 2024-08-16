// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package integration

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"

	"github.com/DataDog/datadog-agent/comp/logs/agent/config"
	integrations "github.com/DataDog/datadog-agent/comp/logs/integrations/def"
	integrationsMock "github.com/DataDog/datadog-agent/comp/logs/integrations/mock"
	pkgConfig "github.com/DataDog/datadog-agent/pkg/config"
	auditor "github.com/DataDog/datadog-agent/pkg/logs/auditor/mock"
	"github.com/DataDog/datadog-agent/pkg/logs/internal/util"
	"github.com/DataDog/datadog-agent/pkg/logs/launchers"
	"github.com/DataDog/datadog-agent/pkg/logs/message"
	"github.com/DataDog/datadog-agent/pkg/logs/pipeline"
	"github.com/DataDog/datadog-agent/pkg/logs/pipeline/mock"
	"github.com/DataDog/datadog-agent/pkg/logs/sources"
	"github.com/DataDog/datadog-agent/pkg/logs/status"
	"github.com/DataDog/datadog-agent/pkg/logs/tailers"
)

type LauncherTestSuite struct {
	suite.Suite
	testDir  string
	testPath string
	testFile *os.File

	outputChan       chan *message.Message
	pipelineProvider pipeline.Provider
	source           *sources.LogSource
	integrationsComp integrations.Component
	s                *Launcher
}

func (suite *LauncherTestSuite) SetupTest() {
	suite.pipelineProvider = mock.NewMockProvider()
	suite.outputChan = suite.pipelineProvider.NextPipelineChan()
	suite.integrationsComp = integrationsMock.Mock()

	var err error
	suite.testDir = suite.T().TempDir()

	suite.testPath = fmt.Sprintf("%s/launcher.log", suite.testDir)

	f, err := os.Create(suite.testPath)
	suite.Nil(err)
	suite.testFile = f

	suite.source = sources.NewLogSource("", &config.LogsConfig{Type: config.IntegrationType, Path: suite.testPath})
	suite.s = NewLauncher(nil, suite.integrationsComp)
	status.InitStatus(pkgConfig.Datadog(), util.CreateSources([]*sources.LogSource{suite.source}))
	suite.s.runPath = suite.testDir
}

func (suite *LauncherTestSuite) TearDownTest() {
	suite.testFile.Close()
}

func (suite *LauncherTestSuite) TestFileCreation() {
	id := "123456789"
	source := sources.NewLogSource("testLogsSource", &config.LogsConfig{Type: config.IntegrationType, Identifier: "123456789", Path: suite.testPath})
	sources.NewLogSources().AddSource(source)

	filePath, err := suite.s.createFile(id)
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), filePath)
}

func (suite *LauncherTestSuite) TestSendLog() {
	logsSources := sources.NewLogSources()
	suite.s.sources = logsSources
	source := sources.NewLogSource("testLogsSource", &config.LogsConfig{Type: config.IntegrationType, Name: "integrationName", Path: suite.testPath, Source: "foo", Service: "bar"})
	filepathChan := make(chan string)
	fileLogChan := make(chan string)
	suite.s.writeFunction = func(filepath, log string) error {
		fileLogChan <- log
		filepathChan <- filepath
		return nil
	}

	id := "123456789"
	filepath, err := suite.s.createFile(id)
	assert.Nil(suite.T(), err)
	suite.s.integrationToFile[source.Name] = filepath
	fileSource := suite.s.makeFileSource(source, filepath)
	assert.Equal(suite.T(), fileSource.Config.Type, config.FileType)
	assert.Equal(suite.T(), source.Config.TailingMode, fileSource.Config.TailingMode)
	assert.Equal(suite.T(), source.Config.Name, fileSource.Config.Name)
	assert.Equal(suite.T(), source.Config.Source, fileSource.Config.Source)
	assert.Equal(suite.T(), source.Config.Service, fileSource.Config.Service)
	assert.Equal(suite.T(), source.Config.Tags, fileSource.Config.Tags)
	suite.s.sources.AddSource(fileSource)

	suite.s.Start(launchers.NewMockSourceProvider(), suite.pipelineProvider, auditor.NewRegistry(), tailers.NewTailerTracker())

	logSample := "hello world"
	suite.integrationsComp.SendLog(logSample, "testLogsSource:HASH1234")

	assert.Equal(suite.T(), logSample, <-fileLogChan)
	assert.Equal(suite.T(), filepath, <-filepathChan)
}

func (suite *LauncherTestSuite) TestWriteLogToFile() {
	logText := "hello world"
	suite.s.writeFunction(suite.testPath, logText)

	fileContents, err := os.ReadFile(suite.testPath)

	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), logText, string(fileContents))
}

// TestIntegrationLogFilePath ensures the filepath for the logs files are correct
func (suite *LauncherTestSuite) TestIntegrationLogFilePath() {
	id := "123456789"
	actualDirectory, actualFilePath := suite.s.integrationLogFilePath(id)

	expectedDirectoryComponents := []string{suite.s.runPath, "integrations"}
	expectedDirectory := strings.Join(expectedDirectoryComponents, "/")

	expectedFilePath := strings.Join([]string{expectedDirectory, id + ".log"}, "/")

	assert.Equal(suite.T(), expectedDirectory, actualDirectory)
	assert.Equal(suite.T(), expectedFilePath, actualFilePath)
}

func TestLauncherTestSuite(t *testing.T) {
	suite.Run(t, new(LauncherTestSuite))
}
