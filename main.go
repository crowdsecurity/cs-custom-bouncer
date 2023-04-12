package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/v22/daemon"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/writer"
	"golang.org/x/sync/errgroup"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"

	"github.com/crowdsecurity/cs-custom-bouncer/pkg/version"
)

const (
	name = "crowdsec-custom-bouncer"
)

func termHandler(sig os.Signal, custom *customBouncer) error {
	if err := custom.ShutDown(); err != nil {
		return err
	}
	return nil
}

func HandleSignals(custom *customBouncer) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan,
		syscall.SIGTERM, syscall.SIGINT)

	exitChan := make(chan int)
	go func() {
		for {
			s := <-signalChan
			switch s {
			// kill -SIGTERM XXXX
			case syscall.SIGTERM, syscall.SIGINT:
				if err := termHandler(s, custom); err != nil {
					log.Fatalf("shutdown fail: %s", err)
				}
				exitChan <- 0
			}
		}
	}()

	code := <-exitChan
	log.Infof("Shutting down custom-bouncer service")
	os.Exit(code)
}

func deleteDecisions(custom *customBouncer, decisions []*models.Decision) {
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

func addDecisions(custom *customBouncer, decisions []*models.Decision) {
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

func main() {
	var err error
	var promServer *http.Server
	configPath := flag.String("c", "", "path to crowdsec-custom-bouncer.yaml")
	verbose := flag.Bool("v", false, "set verbose mode")
	bouncerVersion := flag.Bool("version", false, "display version and exit")
	testConfig := flag.Bool("t", false, "test config and exit")

	flag.Parse()

	if *bouncerVersion {
		fmt.Print(version.ShowStr())
		os.Exit(0)
	}

	if configPath == nil || *configPath == "" {
		log.Fatalf("configuration file is required")
	}

	log.AddHook(&writer.Hook{ // Send logs with level fatal to stderr
		Writer: os.Stderr,
		LogLevels: []log.Level{
			log.PanicLevel,
			log.FatalLevel,
		},
	})

	configBytes, err := mergedConfig(*configPath)
	if err != nil {
		log.Fatalf("unable to read config file: %s", err)
	}

	config, err := newConfig(bytes.NewReader(configBytes))
	if err != nil {
		log.Fatalf("unable to load configuration: %s", err)
	}

	if *verbose {
		log.SetLevel(log.DebugLevel)
	}

	custom, err := newCustomBouncer(config)
	if err != nil {
		log.Fatal(err)
	}

	if *testConfig {
		log.Info("config is valid")
		os.Exit(0)
	}

	if err := custom.Init(); err != nil {
		log.Fatal(err)
	}

	bouncer := &csbouncer.StreamBouncer{}
	bouncer.UserAgent = fmt.Sprintf("%s/%s", name, version.VersionStr())

	err = bouncer.ConfigReader(bytes.NewReader(configBytes))
	if err != nil {
		log.Fatalf("unable to configure bouncer: %s", err)
	}

	if err := bouncer.Init(); err != nil {
		log.Fatal(err)
	}
	cacheResetTicker := time.NewTicker(config.CacheRetentionDuration)

	g, ctx := errgroup.WithContext(context.Background())

	g.Go(func() error {
		bouncer.Run(ctx)
		return fmt.Errorf("stream init failed")
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
			f := func() error {
				log.Debugf("Starting binary %s %s", config.BinPath, config.BinArgs)
				c := exec.CommandContext(ctx, config.BinPath, config.BinArgs...)
				s, err := c.StdinPipe()
				if err != nil {
					return err
				}
				custom.binaryStdin = s
				if err := c.Start(); err != nil {
					return err
				}

				return c.Wait()
			}
			var err error
			if config.TotalRetries == -1 {
				for {
					err := f()
					log.Errorf("Binary exited: %s", err)
				}
			} else {
				for i := 1; i <= config.TotalRetries; i++ {
					err = f()
					log.Errorf("Binary exited (retry %d/%d): %s", i, config.TotalRetries, err)
				}
			}
			return fmt.Errorf("maximum retries exceeded for binary. Exiting")
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
		go HandleSignals(custom)
	}

	if err := g.Wait(); err != nil {
		log.Fatal(err)
	}
}
