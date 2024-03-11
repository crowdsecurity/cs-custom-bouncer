package cmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/v22/daemon"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/crowdsecurity/go-cs-lib/csstring"
	"github.com/crowdsecurity/go-cs-lib/version"

	"github.com/crowdsecurity/cs-custom-bouncer/pkg/cfg"
	"github.com/crowdsecurity/cs-custom-bouncer/pkg/custom"
)

const name = "crowdsec-custom-bouncer"

func bouncerShutdown(custom *custom.CustomBouncer) {
	log.Info("shutting down custom-bouncer service")
	if err := custom.ShutDown(); err != nil {
		log.Errorf("while shutting down custom-bouncer service: %s", err)
	}
}

func HandleSignals(ctx context.Context) error {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, os.Interrupt)

	select {
	case s := <-signalChan:
		switch s {
		case syscall.SIGTERM:
			return errors.New("received SIGTERM")
		case os.Interrupt: // cross-platform SIGINT
			return errors.New("received interrupt")
		}
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

func deleteDecisions(custom *custom.CustomBouncer, decisions []*models.Decision) {
	if len(decisions) == 1 {
		log.Infof("deleting 1 decision")
	} else {
		log.Infof("deleting %d decisions", len(decisions))
	}
	for _, d := range decisions {
		if err := custom.Delete(d); err != nil {
			log.Errorf("unable to delete decision for '%s': %s", *d.Value, err)
			continue
		}
		log.Debugf("deleted '%s'", *d.Value)
	}
}

func addDecisions(custom *custom.CustomBouncer, decisions []*models.Decision) {
	if len(decisions) == 1 {
		log.Infof("adding 1 decision")
	} else {
		log.Infof("adding %d decisions", len(decisions))
	}
	for _, d := range decisions {
		if err := custom.Add(d); err != nil {
			log.Errorf("unable to insert decision for '%s': %s", *d.Value, err)
			continue
		}
		log.Debugf("Adding '%s' for '%s'", *d.Value, *d.Duration)
	}
}

func feedViaStdin(ctx context.Context, custom *custom.CustomBouncer, config *cfg.BouncerConfig) error {
	f := func() error {
		log.Debugf("Starting binary %s %s", config.BinPath, config.BinArgs)
		c := exec.CommandContext(ctx, config.BinPath, config.BinArgs...)
		s, err := c.StdinPipe()
		if err != nil {
			return err
		}
		custom.BinaryStdin = s
		if err := c.Start(); err != nil {
			return err
		}

		return c.Wait()
	}
	var err error
	if config.TotalRetries == -1 {
		for {
			err = f()
			log.Errorf("Binary exited: %s", err)
		}
	} else {
		for i := 1; i <= config.TotalRetries; i++ {
			err = f()
			log.Errorf("Binary exited (retry %d/%d): %s", i, config.TotalRetries, err)
		}
	}
	return errors.New("maximum retries exceeded for binary. Exiting")
}

func Execute() error {
	var promServer *http.Server
	configPath := flag.String("c", "", "path to crowdsec-custom-bouncer.yaml")
	verbose := flag.Bool("v", false, "set verbose mode")
	bouncerVersion := flag.Bool("version", false, "display version and exit")
	testConfig := flag.Bool("t", false, "test config and exit")
	showConfig := flag.Bool("T", false, "show full config (.yaml + .yaml.local) and exit")

	flag.Parse()

	if *bouncerVersion {
		fmt.Print(version.FullString())
		return nil
	}

	if configPath == nil || *configPath == "" {
		return errors.New("configuration file is required")
	}

	configMerged, err := cfg.MergedConfig(*configPath)
	if err != nil {
		return fmt.Errorf("unable to read config file: %w", err)
	}

	if *showConfig {
		fmt.Println(string(configMerged))
		return nil
	}

	configExpanded := csstring.StrictExpand(string(configMerged), os.LookupEnv)

	config, err := cfg.NewConfig(strings.NewReader(configExpanded))
	if err != nil {
		return fmt.Errorf("unable to load configuration: %w", err)
	}

	if *verbose && log.GetLevel() < log.DebugLevel {
		log.SetLevel(log.DebugLevel)
	}

	custom, err := custom.NewCustomBouncer(config)
	if err != nil {
		return err
	}

	log.Infof("Starting %s %s", name, version.String())

	if err = custom.Init(); err != nil {
		return err
	}

	if *testConfig {
		log.Info("config is valid")
		return nil
	}

	defer bouncerShutdown(custom)

	bouncer := &csbouncer.StreamBouncer{}
	bouncer.UserAgent = fmt.Sprintf("%s/%s", name, version.String())

	err = bouncer.ConfigReader(strings.NewReader(configExpanded))
	if err != nil {
		return fmt.Errorf("unable to configure bouncer: %w", err)
	}

	if err := bouncer.Init(); err != nil {
		return err
	}
	cacheResetTicker := time.NewTicker(config.CacheRetentionDuration)

	g, ctx := errgroup.WithContext(context.Background())

	g.Go(func() error {
		bouncer.Run(ctx)
		return errors.New("bouncer stream halted")
	})

	if config.PrometheusConfig.Enabled {
		listenOn := net.JoinHostPort(
			config.PrometheusConfig.ListenAddress,
			config.PrometheusConfig.ListenPort,
		)
		muxer := http.NewServeMux()
		promServer = &http.Server{
			Addr: net.JoinHostPort(
				config.PrometheusConfig.ListenAddress,
				config.PrometheusConfig.ListenPort,
			),
			Handler: muxer,
		}
		muxer.Handle("/metrics", promhttp.Handler())
		prometheus.MustRegister(csbouncer.TotalLAPICalls, csbouncer.TotalLAPIError)
		go func() {
			log.Infof("Serving metrics at %s", listenOn+"/metrics")
			log.Error(promServer.ListenAndServe())
			// don't need to cancel context here, prometheus is not critical
		}()
	}

	if config.FeedViaStdin {
		g.Go(func() error {
			return feedViaStdin(ctx, custom, config)
		})
	}

	g.Go(func() error {
		log.Infof("Processing new and deleted decisions . . .")
		for {
			select {
			case <-ctx.Done():
				log.Infoln("terminating bouncer process")
				if config.PrometheusConfig.Enabled {
					log.Infoln("terminating prometheus server")
					if err := promServer.Shutdown(context.Background()); err != nil {
						log.Errorf("unable to shutdown prometheus server: %s", err)
					}
				}
				return nil
			case decisions := <-bouncer.Stream:
				if decisions == nil {
					continue
				}
				deleteDecisions(custom, decisions.Deleted)
				addDecisions(custom, decisions.New)
			case <-cacheResetTicker.C:
				custom.ResetCache()
			}
		}
	})

	if config.Daemon {
		sent, err := daemon.SdNotify(false, "READY=1")
		if !sent && err != nil {
			log.Errorf("Failed to notify: %v", err)
		}
		g.Go(func() error {
			return HandleSignals(ctx)
		})
	}

	if err := g.Wait(); err != nil {
		return fmt.Errorf("process terminated with error: %w", err)
	}

	return nil
}
