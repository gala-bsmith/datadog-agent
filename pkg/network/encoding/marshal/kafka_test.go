// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package marshal

import (
	"runtime"
	"testing"

	model "github.com/DataDog/agent-payload/v5/process"
	"github.com/gogo/protobuf/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/DataDog/datadog-agent/pkg/network"
	"github.com/DataDog/datadog-agent/pkg/network/protocols/kafka"
	"github.com/DataDog/datadog-agent/pkg/process/util"
)

func skipIfNotLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the feature is only supported on linux.")
	}
}

const (
	clientPort  = uint16(1234)
	serverPort  = uint16(12345)
	topicName   = "TopicName"
	apiVersion1 = 1
	apiVersion2 = 1
)

var (
	localhost = util.AddressFromString("127.0.0.1")
)

type KafkaSuite struct {
	suite.Suite
}

func TestKafkaStats(t *testing.T) {
	skipIfNotLinux(t)
	suite.Run(t, &KafkaSuite{})
}

func (s *KafkaSuite) TestFormatKafkaStats() {
	t := s.T()

	kafkaKey1 := kafka.NewKey(
		localhost,
		localhost,
		clientPort,
		serverPort,
		topicName,
		kafka.ProduceAPIKey,
		apiVersion1,
	)
	kafkaKey2 := kafka.NewKey(
		localhost,
		localhost,
		clientPort,
		serverPort,
		topicName,
		kafka.FetchAPIKey,
		apiVersion2,
	)

	defaultConnection := network.ConnectionStats{
		Source: localhost,
		Dest:   localhost,
		SPort:  clientPort,
		DPort:  serverPort,
		KafkaStats: []network.USMKeyValue[kafka.Key, *kafka.RequestStat]{
			{Key: kafkaKey1, Value: &kafka.RequestStat{Count: 10}},
			{Key: kafkaKey2, Value: &kafka.RequestStat{Count: 2}},
		},
	}

	in := &network.Connections{
		BufferedData: network.BufferedData{
			Conns: []network.ConnectionStats{
				defaultConnection,
			},
		},
	}
	out := &model.DataStreamsAggregations{
		KafkaAggregations: []*model.KafkaAggregation{
			{
				Header: &model.KafkaRequestHeader{
					RequestType:    kafka.ProduceAPIKey,
					RequestVersion: apiVersion1,
				},
				Topic: "TopicName",
				Count: 10,
			},
			{
				Header: &model.KafkaRequestHeader{
					RequestType:    kafka.FetchAPIKey,
					RequestVersion: apiVersion2,
				},
				Topic: "TopicName",
				Count: 2,
			},
		},
	}

	encoder := newKafkaEncoder()
	t.Cleanup(encoder.Close)

	aggregations := getKafkaAggregations(t, encoder, in.Conns[0])

	require.NotNil(t, aggregations)
	assert.ElementsMatch(t, out.KafkaAggregations, aggregations.KafkaAggregations)
}

func (s *KafkaSuite) TestKafkaIDCollisionRegression() {
	t := s.T()
	assert := assert.New(t)
	kafkaKey := kafka.NewKey(
		localhost,
		localhost,
		clientPort,
		serverPort,
		topicName,
		kafka.ProduceAPIKey,
		apiVersion1,
	)

	connections := []network.ConnectionStats{
		{
			Source: localhost,
			SPort:  clientPort,
			Dest:   localhost,
			DPort:  serverPort,
			Pid:    1,
			KafkaStats: []network.USMKeyValue[kafka.Key, *kafka.RequestStat]{
				{Key: kafkaKey, Value: &kafka.RequestStat{Count: 10}},
			},
		},
		{
			Source: localhost,
			SPort:  clientPort,
			Dest:   localhost,
			DPort:  serverPort,
			Pid:    2,
		},
	}

	in := &network.Connections{
		BufferedData: network.BufferedData{
			Conns: connections,
		},
	}

	encoder := newKafkaEncoder()
	t.Cleanup(encoder.Close)
	aggregations := getKafkaAggregations(t, encoder, in.Conns[0])

	// assert that the first connection matching the Kafka data will get back a non-nil result
	assert.Equal(topicName, aggregations.KafkaAggregations[0].Topic)
	assert.Equal(uint32(10), aggregations.KafkaAggregations[0].Count)

	// assert that the other connections sharing the same (source,destination)
	// addresses but different PIDs *won't* be associated with the Kafka stats
	// object
	assert.Nil(encoder.GetKafkaAggregations(in.Conns[1]))
}

func getKafkaAggregations(t *testing.T, encoder *kafkaEncoder, c network.ConnectionStats) *model.DataStreamsAggregations {
	kafkaBlob := encoder.GetKafkaAggregations(c)
	require.NotNil(t, kafkaBlob)

	aggregations := new(model.DataStreamsAggregations)
	err := proto.Unmarshal(kafkaBlob, aggregations)
	require.NoError(t, err)

	return aggregations
}
