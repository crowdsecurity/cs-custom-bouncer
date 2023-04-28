package cfg

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

type BouncerConfig struct {
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

// MergedConfig() returns the byte content of the patched configuration file (with .yaml.local).
func MergedConfig(configPath string) ([]byte, error) {
	patcher := yamlpatch.NewPatcher(configPath, ".local")
	data, err := patcher.MergedPatchContent()
	if err != nil {
		return nil, err
	}
	return data, nil
}

func NewConfig(reader io.Reader) (*BouncerConfig, error) {
	var LogOutput *lumberjack.Logger //io.Writer

	config := &BouncerConfig{}

	fcontent, err := io.ReadAll(reader)
	if err != nil {
		return &BouncerConfig{}, err
	}

	err = yaml.Unmarshal(fcontent, &config)
	if err != nil {
		return &BouncerConfig{}, fmt.Errorf("failed to unmarshal: %w", err)
	}

	if config.BinPath == "" {
		return &BouncerConfig{}, fmt.Errorf("bin_path is not set")
	}
	if config.LogMode == "" {
		return &BouncerConfig{}, fmt.Errorf("log_mode is not net")
	}

	_, err = os.Stat(config.BinPath)
	if os.IsNotExist(err) {
		return config, fmt.Errorf("binary '%s' doesn't exist", config.BinPath)
	}

	/*Configure logging*/
	if err := types.SetDefaultLoggerConfig(config.LogMode, config.LogDir, config.LogLevel, config.LogMaxSize, config.LogMaxFiles, config.LogMaxAge, config.CompressLogs, false); err != nil {
		log.Fatal(err)
	}
	if config.LogMode == "file" {
		if config.LogDir == "" {
			config.LogDir = "/var/log/"
		}
		_maxsize := 500
		if config.LogMaxSize != 0 {
			_maxsize = config.LogMaxSize
		}
		_maxfiles := 3
		if config.LogMaxFiles != 0 {
			_maxfiles = config.LogMaxFiles
		}
		_maxage := 30
		if config.LogMaxAge != 0 {
			_maxage = config.LogMaxAge
		}
		_compress := true
		if config.CompressLogs != nil {
			_compress = *config.CompressLogs
		}
		LogOutput = &lumberjack.Logger{
			Filename:   config.LogDir + "/crowdsec-custom-bouncer.log",
			MaxSize:    _maxsize, //megabytes
			MaxBackups: _maxfiles,
			MaxAge:     _maxage,   //days
			Compress:   _compress, //disabled by default
		}
		log.SetOutput(LogOutput)
		log.SetFormatter(&log.TextFormatter{TimestampFormat: "02-01-2006 15:04:05", FullTimestamp: true})
	} else if config.LogMode != "stdout" {
		return &BouncerConfig{}, fmt.Errorf("log mode '%s' unknown, expecting 'file' or 'stdout'", config.LogMode)
	}

	if config.CacheRetentionDuration == 0 {
		log.Infof("cache_retention_duration defaults to 10 seconds")
		config.CacheRetentionDuration = 10 * time.Second
	}

	return config, nil
}
