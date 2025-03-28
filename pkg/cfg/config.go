package cfg

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/go-cs-lib/yamlpatch"
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
	Logging                    LoggingConfig    `yaml:",inline"`
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
	config := &BouncerConfig{}

	fcontent, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(fcontent, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal: %w", err)
	}

	if err = config.Logging.setup("crowdsec-custom-bouncer.log"); err != nil {
		return nil, err
	}

	if config.BinPath == "" {
		return nil, errors.New("bin_path is not set")
	}

	_, err = os.Stat(config.BinPath)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("binary '%s' doesn't exist", config.BinPath)
	}

	if config.CacheRetentionDuration == 0 {
		log.Info("cache_retention_duration defaults to 10 seconds")
		config.CacheRetentionDuration = 10 * time.Second
	}

	if config.TotalRetries == 0 {
		config.TotalRetries = 1
	}

	return config, nil
}
