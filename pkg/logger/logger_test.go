// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License").
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
//limitations under the License.

package logger

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

func TestEnvLogFilePath(t *testing.T) {
	path := "/var/log/test.log"
	_ = os.Setenv(envLogFilePath, path)
	defer os.Unsetenv(envLogFilePath)

	assert.Equal(t, path, GetLogLocation())
}

func TestLoggerGetSameInstance(t *testing.T) {
	log1 := Get()
	log2 := Get()

	assert.True(t, log1 == log2)
}

func TestLoggerNewAndGetSameInstance(t *testing.T) {
	logConfig := LoadLogConfig()
	log1 := New(logConfig)
	log2 := Get()

	assert.True(t, log1 == log2)
}

func TestGetLogFileLocationReturnsDefaultPath(t *testing.T) {
	defaultPath := "/var/log/aws-routed-eni/ebpf-sdk.log"
	assert.Equal(t, defaultPath, GetLogLocation())
}

func TestLogLevelReturnsOverriddenLevel(t *testing.T) {
	_ = os.Setenv(envLogLevel, "INFO")
	defer os.Unsetenv(envLogLevel)

	expectedLogLevel := zapcore.InfoLevel
	inputLogLevel := GetLogLevel()
	assert.Equal(t, expectedLogLevel, getZapLevel(inputLogLevel))
}

func TestLogLevelReturnsDefaultLevelWhenEnvNotSet(t *testing.T) {
	expectedLogLevel := zapcore.DebugLevel
	inputLogLevel := GetLogLevel()
	assert.Equal(t, expectedLogLevel, getZapLevel(inputLogLevel))
}

func TestLogLevelReturnsDefaultLevelWhenEnvSetToInvalidValue(t *testing.T) {
	_ = os.Setenv(envLogLevel, "EVERYTHING")
	defer os.Unsetenv(envLogLevel)

	var expectedLogLevel zapcore.Level
	inputLogLevel := GetLogLevel()
	expectedLogLevel = zapcore.DebugLevel
	assert.Equal(t, expectedLogLevel, getZapLevel(inputLogLevel))
}

func TestGetSDKLogFilePathEmpty(t *testing.T) {
	expectedWriter := zapcore.Lock(os.Stderr)
	inputSDKLogFile := ""
	assert.Equal(t, expectedWriter, getSDKLogFilePath(inputSDKLogFile))
}

func TestGetSDKLogFilePathStdout(t *testing.T) {
	expectedWriter := zapcore.Lock(os.Stdout)
	inputSDKLogFile := "stdout"
	assert.Equal(t, expectedWriter, getSDKLogFilePath(inputSDKLogFile))
}

func TestGetSDKLogFilePath(t *testing.T) {
	inputSDKLogFile := "/var/log/aws-routed-eni/ebpf-sdk.log"
	expectedLumberJackLogger := &lumberjack.Logger{
		Filename:   "/var/log/aws-routed-eni/ebpf-sdk.log",
		MaxSize:    100,
		MaxBackups: 5,
		MaxAge:     30,
		Compress:   true,
	}
	assert.Equal(t, zapcore.AddSync(expectedLumberJackLogger), getSDKLogFilePath(inputSDKLogFile))
}
