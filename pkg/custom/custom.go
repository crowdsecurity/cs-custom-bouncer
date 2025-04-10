package custom

import (
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/models"

	"github.com/crowdsecurity/cs-custom-bouncer/pkg/cfg"
)

type DecisionKey struct {
	Value string
	Type  string
}

type DecisionWithAction struct {
	models.Decision
	ID     int64  `json:"id"`
	Action string `json:"action,omitempty"`
}

type CustomBouncer struct {
	Path                    string
	BinaryStdin             io.Writer
	feedViaStdin            bool
	newDecisionValueSet     map[DecisionKey]struct{}
	expiredDecisionValueSet map[DecisionKey]struct{}
}

func NewCustomBouncer(cfg *cfg.BouncerConfig) (*CustomBouncer, error) {
	return &CustomBouncer{
		Path:         cfg.BinPath,
		feedViaStdin: cfg.FeedViaStdin,
	}, nil
}

func (c *CustomBouncer) ResetCache() {
	cachedDecisionCount := len(c.newDecisionValueSet) + len(c.expiredDecisionValueSet)
	if cachedDecisionCount != 0 {
		log.Debugf("resetting cache, clearing %d decisions", cachedDecisionCount)
		// dont return here, because this could be used to intiate the sets
	}
	c.newDecisionValueSet = make(map[DecisionKey]struct{})
	c.expiredDecisionValueSet = make(map[DecisionKey]struct{})
}

func (c *CustomBouncer) Init() error {
	c.ResetCache()
	return nil
}

func (c *CustomBouncer) Add(decision *models.Decision) error {
	if _, exists := c.newDecisionValueSet[decisionToDecisionKey(decision)]; exists {
		return nil
	}
	banDuration, err := time.ParseDuration(*decision.Duration)
	if err != nil {
		return err
	}
	log.Debugf("custom [%s] : add ban on %s for %s sec (%s)", c.Path, *decision.Value, strconv.Itoa(int(banDuration.Seconds())), *decision.Scenario)
	var str string
	if c.feedViaStdin {
		str, err = serializeDecision(decision, "add")
	} else {
		str, err = serializeDecision(decision, "")
	}
	if err != nil {
		log.Warningf("serialize: %s", err)
	}
	if c.feedViaStdin {
		fmt.Fprintln(c.BinaryStdin, str)
		c.newDecisionValueSet[decisionToDecisionKey(decision)] = struct{}{}
		return nil
	}
	cmd := exec.Command(c.Path, "add", *decision.Value, strconv.Itoa(int(banDuration.Seconds())), *decision.Scenario, str)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Errorf("Error in 'add' command (%s): %v --> %s", cmd.String(), err, string(out))
	}
	c.newDecisionValueSet[decisionToDecisionKey(decision)] = struct{}{}
	return nil
}

func (c *CustomBouncer) Delete(decision *models.Decision) error {
	if _, exists := c.expiredDecisionValueSet[decisionToDecisionKey(decision)]; exists {
		return nil
	}
	banDuration, err := time.ParseDuration(*decision.Duration)
	if err != nil {
		return err
	}
	var str string
	if c.feedViaStdin {
		str, err = serializeDecision(decision, "del")
	} else {
		str, err = serializeDecision(decision, "")
	}
	if c.feedViaStdin {
		fmt.Fprintln(c.BinaryStdin, str)
		c.expiredDecisionValueSet[decisionToDecisionKey(decision)] = struct{}{}
		return nil
	}
	if err != nil {
		log.Warningf("serialize: %s", err)
	}
	log.Debugf("custom [%s] : del ban on %s for %s sec (%s)", c.Path, *decision.Value, strconv.Itoa(int(banDuration.Seconds())), *decision.Scenario)
	cmd := exec.Command(c.Path, "del", *decision.Value, strconv.Itoa(int(banDuration.Seconds())), *decision.Scenario, str)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Errorf("Error in 'del' command (%s): %v --> %s", cmd.String(), err, string(out))
	}
	c.expiredDecisionValueSet[decisionToDecisionKey(decision)] = struct{}{}
	return nil
}

func (*CustomBouncer) ShutDown() error {
	return nil
}

func serializeDecision(decision *models.Decision, action string) (string, error) {
	d := DecisionWithAction{Decision: *decision, Action: action, ID: decision.ID}
	serbyte, err := json.Marshal(d)
	if err != nil {
		return "", fmt.Errorf("serialize error : %w", err)
	}
	return string(serbyte), nil
}

func decisionToDecisionKey(decision *models.Decision) DecisionKey {
	return DecisionKey{
		Value: *decision.Value,
		Type:  *decision.Type,
	}
}
