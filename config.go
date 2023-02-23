package main

import (
	"fmt"
	"io"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/crowdsecurity/crowdsec/pkg/yamlpatch"
)

type PrometheusConfig struct {
	Enabled       bool   `yaml:"enabled"`
	ListenAddress string `yaml:"listen_addr"`
	ListenPort    string `yaml:"listen_port"`
}

type bouncerConfig struct {
	BinPath                    string           `yaml:"bin_path"` // path to binary
	BinArgs                    []string         `yaml:"bin_args"` // arguments for binary
	PidDir                     string           `yaml:"piddir"`
	UpdateFrequency            string           `yaml:"update_frequency"`
	IncludeScenariosContaining []string         `yaml:"include_scenarios_containing"`
	ExcludeScenariosContaining []string         `yaml:"exclude_scenarios_containing"`
	OnlyIncludeDecisionsFrom   []string         `yaml:"only_include_decisions_from"`
	Daemon                     bool             `yaml:"daemonize"`
	LogMode                    string           `yaml:"log_mode"`
	LogDir                     string           `yaml:"log_dir"`
	LogLevel                   log.Level        `yaml:"log_level"`
	LogMaxSize                 int              `yaml:"log_max_size,omitempty"`
	LogMaxFiles                int              `yaml:"log_max_files,omitempty"`
	LogMaxAge                  int              `yaml:"log_max_age,omitempty"`
	CompressLogs               *bool            `yaml:"compress_logs,omitempty"`
	APIUrl                     string           `yaml:"api_url"`
	APIKey                     string           `yaml:"api_key"`
	CacheRetentionDuration     time.Duration    `yaml:"cache_retention_duration"`
	FeedViaStdin               bool             `yaml:"feed_via_stdin"`
	TotalRetries               int              `yaml:"total_retries"`
	PrometheusConfig           PrometheusConfig `yaml:"prometheus"`
}

// mergedConfig() returns the byte content of the patched configuration file (with .yaml.local).
func mergedConfig(configPath string) ([]byte, error) {
	patcher := yamlpatch.NewPatcher(configPath, ".local")
	data, err := patcher.MergedPatchContent()
	if err != nil {
		return nil, err
	}
	return data, nil
}

func newConfig(reader io.Reader) (*bouncerConfig, error) {
	var LogOutput *lumberjack.Logger //io.Writer

	config := &bouncerConfig{}

	fcontent, err := io.ReadAll(reader)
	if err != nil {
		return &bouncerConfig{}, err
	}

	err = yaml.Unmarshal(fcontent, &config)
	if err != nil {
		return &bouncerConfig{}, fmt.Errorf("failed to unmarshal: %w", err)
	}

	if config.BinPath == "" {
		return &bouncerConfig{}, fmt.Errorf("bin_path is not set")
	}
	if config.LogMode == "" {
		return &bouncerConfig{}, fmt.Errorf("log_mode is not net")
	}

	_, err = os.Stat(config.BinPath)
	if os.IsNotExist(err) {
		return config, fmt.Errorf("binary '%s' doesn't exist", config.BinPath)
	}

	/*Configure logging*/
	if err := types.SetDefaultLoggerConfig(config.LogMode, config.LogDir, config.LogLevel, config.LogMaxSize, config.LogMaxFiles, config.LogMaxAge, config.CompressLogs, false); err != nil {
		log.Fatal(err.Error())
	}
	if config.LogMode == "file" {
		if config.LogDir == "" {
			config.LogDir = "/var/log/"
		}
		LogOutput = &lumberjack.Logger{
			Filename:   config.LogDir + "/crowdsec-custom-bouncer.log",
			MaxSize:    500, //megabytes
			MaxBackups: 3,
			MaxAge:     28,   //days
			Compress:   true, //disabled by default
		}
		log.SetOutput(LogOutput)
		log.SetFormatter(&log.TextFormatter{TimestampFormat: "02-01-2006 15:04:05", FullTimestamp: true})
	} else if config.LogMode != "stdout" {
		return &bouncerConfig{}, fmt.Errorf("log mode '%s' unknown, expecting 'file' or 'stdout'", config.LogMode)
	}

	if config.CacheRetentionDuration == 0 {
		log.Infof("cache_retention_duration defaults to 10 seconds")
		config.CacheRetentionDuration = time.Duration(10 * time.Second)
	}

	return config, nil
}
