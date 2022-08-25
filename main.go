package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/daemon"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/writer"

	"github.com/crowdsecurity/crowdsec-custom-bouncer/pkg/version"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"gopkg.in/tomb.v2"
)

const (
	name = "crowdsec-custom-bouncer"
)

var t tomb.Tomb

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

func main() {
	var err error
	configPath := flag.String("c", "", "path to crowdsec-custom-bouncer.yaml")
	verbose := flag.Bool("v", false, "set verbose mode")
	bouncerVersion := flag.Bool("version", false, "display version and exit")

	flag.Parse()

	if *bouncerVersion {
		fmt.Printf("%s", version.ShowStr())
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

	config, err := NewConfig(*configPath)
	if err != nil {
		log.Fatalf("unable to load configuration: %s", err)
	}

	if *verbose {
		log.SetLevel(log.DebugLevel)
	}

	custom, err := newCustomBouncer(config)
	if err != nil {
		log.Fatalf(err.Error())
	}

	if err := custom.Init(); err != nil {
		log.Fatalf(err.Error())
	}

	bouncer := &csbouncer.StreamBouncer{}
	bouncer.UserAgent = fmt.Sprintf("%s/%s", name, version.VersionStr())

	err = bouncer.Config(*configPath)
	if err != nil {
		log.Error(err.Error())
		return
	}

	if err := bouncer.Init(); err != nil {
		log.Error(err.Error())
		return
	}
	cacheResetTicker := time.NewTicker(config.CacheRetentionDuration)

	t.Go(func() error {
		bouncer.Run()
		return fmt.Errorf("stream api init failed")
	})
	if config.PrometheusConfig.Enabled {
		prometheus.MustRegister(csbouncer.TotalLAPICalls, csbouncer.TotalLAPIError)
		go func() {
			http.Handle("/metrics", promhttp.Handler())
			listenOn := net.JoinHostPort(
				config.PrometheusConfig.ListenAddress,
				config.PrometheusConfig.ListenPort,
			)
			log.Infof("Serving metrics at %s", listenOn+"/metrics")
			log.Error(http.ListenAndServe(listenOn, nil))
		}()
	}
	go bouncer.Run()
	if config.FeedViaStdin {
		t.Go(
			func() error {
				f := func() error {
					c := exec.Command(config.BinPath)
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
						log.Error(err)
					}
				} else {
					for i := 0; i <= config.TotalRetries; i++ {
						err = f()
					}
				}
				log.Error("maximum retries exceeded for binary. Exiting")
				t.Kill(err)
				return err

			},
		)

	}

	t.Go(func() error {
		log.Printf("Processing new and deleted decisions . . .")
		for {
			select {
			case <-t.Dying():
				log.Infoln("terminating bouncer process")
				return nil
			case decisions := <-bouncer.Stream:
				log.Infof("deleting '%d' decisions", len(decisions.Deleted))
				for _, decision := range decisions.Deleted {
					if err := custom.Delete(decision); err != nil {
						log.Errorf("unable to delete decision for '%s': %s", *decision.Value, err)
					} else {
						log.Debugf("deleted '%s'", *decision.Value)
					}

				}
				log.Infof("adding '%d' decisions", len(decisions.New))
				for _, decision := range decisions.New {
					if err := custom.Add(decision); err != nil {
						log.Errorf("unable to insert decision for '%s': %s", *decision.Value, err)
					} else {
						log.Debugf("Adding '%s' for '%s'", *decision.Value, *decision.Duration)
					}
				}
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

	if err := t.Wait(); err != nil {
		log.Errorf("process return with error: %s", err)
	}
}
