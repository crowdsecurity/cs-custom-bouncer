package main

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

type customBouncer struct {
	path string
}

func newCustomBouncer(path string) (*customBouncer, error) {
	return &customBouncer{
		path: path,
	}, nil
}

func (c *customBouncer) Init() error {
	return nil
}

func (c *customBouncer) Add(decision *models.Decision) error {
	banDuration, err := time.ParseDuration(*decision.Duration)
	if err != nil {
		return err
	}
	log.Printf("custom [%s] : add ban on %s for %s sec (%s)", c.path, *decision.Value, strconv.Itoa(int(banDuration.Seconds())), *decision.Scenario)

	str, err := serializeDecision(decision)
	if err != nil {
		log.Warningf("serialize: %s", err)
	}
	cmd := exec.Command(c.path, "add", *decision.Value, strconv.Itoa(int(banDuration.Seconds())), *decision.Scenario, str)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Infof("Error in 'add' command (%s): %v --> %s", cmd.String(), err, string(out))
	}
	return nil
}

func (c *customBouncer) Delete(decision *models.Decision) error {
	banDuration, err := time.ParseDuration(*decision.Duration)
	if err != nil {
		return err
	}

	str, err := serializeDecision(decision)
	if err != nil {
		log.Warningf("serialize: %s", err)
	}
	log.Printf("custom [%s] : del ban on %s for %s sec (%s)", c.path, *decision.Value, strconv.Itoa(int(banDuration.Seconds())), *decision.Scenario)
	cmd := exec.Command(c.path, "del", *decision.Value, strconv.Itoa(int(banDuration.Seconds())), *decision.Scenario, str)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Infof("Error in 'del' command (%s): %v --> %s", cmd.String(), err, string(out))
	}
	return nil
}

func (c *customBouncer) ShutDown() error {
	return nil
}

func serializeDecision(decision *models.Decision) (string, error) {
	serbyte, err := json.Marshal(decision)
	if err != nil {
		return "", fmt.Errorf("serialize error : %s", err)
	}
	return string(serbyte), nil
}
