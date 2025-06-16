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
	"runtime"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	defaultLogFilePath = "/var/log/aws-routed-eni/ebpf-sdk.log"
	defaultLogLevel    = "Info"
	envLogLevel        = "AWS_EBPF_SDK_LOGLEVEL"
	envLogFilePath     = "AWS_EBPF_SDK_LOG_FILE"
)

// Log is global variable so that log functions can be directly accessed
var log Logger

// Fields Type to pass when we want to call WithFields for structured logging
type Fields map[string]interface{}

// Logger is our contract for the logger
type Logger interface {
	Debugf(format string, args ...interface{})

	Debug(format string)

	Infof(format string, args ...interface{})

	Info(format string)

	Warnf(format string, args ...interface{})

	Warn(format string)

	Errorf(format string, args ...interface{})

	Error(format string)

	Fatalf(format string, args ...interface{})

	Panicf(format string, args ...interface{})

	WithFields(keyValues Fields) Logger
}

// Configuration stores the config for the logger
type Configuration struct {
	LogLevel    string
	LogLocation string
}

// LoadLogConfig returns the log configuration
func LoadLogConfig() *Configuration {
	return &Configuration{
		LogLevel:    GetLogLevel(),
		LogLocation: GetLogLocation(),
	}
}

// GetLogLocation returns the log file path
func GetLogLocation() string {
	logFilePath := os.Getenv(envLogFilePath)
	if logFilePath == "" {
		logFilePath = defaultLogFilePath
	}
	return logFilePath
}

// GetLogLevel returns the log level
func GetLogLevel() string {
	logLevel := os.Getenv(envLogLevel)
	switch logLevel {
	case "":
		logLevel = defaultLogLevel
		return logLevel
	default:
		return logLevel
	}
}

type structuredLogger struct {
	zapLogger *zap.SugaredLogger
}

// getZapLevel converts log level string to zapcore.Level
func getZapLevel(inputLogLevel string) zapcore.Level {
	lvl := strings.ToLower(inputLogLevel)

	switch lvl {
	case "debug":
		return zapcore.DebugLevel
	case "info":
		return zapcore.InfoLevel
	case "warn":
		return zapcore.WarnLevel
	case "error":
		return zapcore.ErrorLevel
	case "fatal":
		return zapcore.FatalLevel
	default:
		return zapcore.DebugLevel
	}
}

func (logf *structuredLogger) Debugf(format string, args ...interface{}) {
	logf.zapLogger.Debugf(format, args...)
}

func (logf *structuredLogger) Debug(format string) {
	logf.zapLogger.Desugar().Debug(format)
}

func (logf *structuredLogger) Infof(format string, args ...interface{}) {
	logf.zapLogger.Infof(format, args...)
}

func (logf *structuredLogger) Info(format string) {
	logf.zapLogger.Desugar().Info(format)
}

func (logf *structuredLogger) Warnf(format string, args ...interface{}) {
	logf.zapLogger.Warnf(format, args...)
}

func (logf *structuredLogger) Warn(format string) {
	logf.zapLogger.Desugar().Warn(format)
}

func (logf *structuredLogger) Error(format string) {
	logf.zapLogger.Desugar().Error(format)
}

func (logf *structuredLogger) Errorf(format string, args ...interface{}) {
	logf.zapLogger.Errorf(format, args...)
}

func (logf *structuredLogger) Fatalf(format string, args ...interface{}) {
	logf.zapLogger.Fatalf(format, args...)
}

func (logf *structuredLogger) Panicf(format string, args ...interface{}) {
	logf.zapLogger.Fatalf(format, args...)
}

func (logf *structuredLogger) WithFields(fields Fields) Logger {
	var f = make([]interface{}, 0)
	for k, v := range fields {
		f = append(f, k)
		f = append(f, v)
	}
	newLogger := logf.zapLogger.With(f...)
	return &structuredLogger{newLogger}
}

func getEncoder() zapcore.Encoder {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	return zapcore.NewJSONEncoder(encoderConfig)
}

func (logConfig *Configuration) newZapLogger() *structuredLogger {
	var cores []zapcore.Core

	logLevel := getZapLevel(logConfig.LogLevel)

	writer := getLogFilePath(logConfig.LogLocation)

	cores = append(cores, zapcore.NewCore(getEncoder(), writer, logLevel))

	combinedCore := zapcore.NewTee(cores...)

	logger := zap.New(combinedCore,
		zap.AddCaller(),
		zap.AddCallerSkip(2),
	)
	defer logger.Sync()
	sugar := logger.Sugar()

	return &structuredLogger{
		zapLogger: sugar,
	}
}

// getLogFilePath returns the writer
func getLogFilePath(logFilePath string) zapcore.WriteSyncer {
	var writer zapcore.WriteSyncer

	if logFilePath == "" {
		writer = zapcore.Lock(os.Stderr)
	} else if strings.ToLower(logFilePath) != "stdout" {
		writer = getLogWriter(logFilePath)
	} else {
		writer = zapcore.Lock(os.Stdout)
	}

	return writer
}

// getLogWriter is for lumberjack
func getLogWriter(logFilePath string) zapcore.WriteSyncer {
	lumberJackLogger := &lumberjack.Logger{
		Filename:   logFilePath,
		MaxSize:    100,
		MaxBackups: 5,
		MaxAge:     30,
		Compress:   true,
	}
	return zapcore.AddSync(lumberJackLogger)
}

// DefaultLogger creates and returns a new default logger.
func DefaultLogger() Logger {
	productionConfig := zap.NewProductionConfig()
	productionConfig.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	productionConfig.EncoderConfig.EncodeCaller = func(caller zapcore.EntryCaller, enc zapcore.PrimitiveArrayEncoder) {
		_, caller.File, caller.Line, _ = runtime.Caller(8)
		enc.AppendString(caller.FullPath())
	}
	logger, _ := productionConfig.Build()
	defer logger.Sync()
	sugar := logger.Sugar()
	return &structuredLogger{
		zapLogger: sugar,
	}
}

// Get returns an default instance of the zap logger
func Get() Logger {
	if log == nil {
		logConfig := LoadLogConfig()
		log = New(logConfig)
		log.Info("Initialized new logger as an existing instance was not found")
	}
	return log
}

// New logger initializes logger
func New(inputLogConfig *Configuration) Logger {
	log = inputLogConfig.newZapLogger()
	log.Info("Constructed new logger instance")
	return log
}
