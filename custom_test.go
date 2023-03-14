package main

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

const (
	binaryPath       = "./test/custom-live"
	binaryOutputFile = "./data.txt"
)

var (
	durationWithUnit  = "1200s"
	durationInSeconds = durationWithUnit[:len(durationWithUnit)-1]
	sceanario         = "crowdsec/bruteforce"
	ip1               = "1.2.3.4"
	ip2               = "1.2.3.5"
	decisionType      = "IP"
)

type parsedLine struct {
	action    string
	value     string
	duration  string
	sceanario string
}

func parseFile(path string) []parsedLine {
	dat, err := os.ReadFile(binaryOutputFile)
	parsedLines := make([]parsedLine, 0)
	if err != nil {
		panic(err)
	}
	for _, line := range strings.Split(string(dat), "\n") {
		if len(line) == 0 {
			continue
		}

		parsedLines = append(parsedLines, parseLine(line))
	}
	return parsedLines
}

func parseLine(line string) parsedLine {
	words := strings.Split(line, " ")
	return parsedLine{
		action:    words[0],
		value:     words[1],
		duration:  words[2],
		sceanario: words[3],
	}
}

func cleanup() {
	if _, err := os.Stat(binaryOutputFile); err != nil {
		fmt.Println("didn't found the file")
		return
	}
	os.Remove(binaryOutputFile)
}

func Test_customBouncer_Add(t *testing.T) {
	type args struct {
		Decisions []*models.Decision
	}
	tests := []struct {
		name          string
		args          args
		expectedLines []parsedLine
	}{
		{
			name: "simple, single decision",
			args: args{
				Decisions: []*models.Decision{
					{
						Duration: &durationWithUnit,
						Value:    &ip1,
						Scenario: &sceanario,
						Type:     &decisionType,
					},
				},
			},
			expectedLines: []parsedLine{
				{
					action:    "add",
					value:     ip1,
					duration:  durationInSeconds,
					sceanario: sceanario,
				},
			},
		},
		{
			name: "simple, two decisions",
			args: args{
				Decisions: []*models.Decision{
					{
						Duration: &durationWithUnit,
						Value:    &ip1,
						Scenario: &sceanario,
						Type:     &decisionType,
					},
					{
						Duration: &durationWithUnit,
						Value:    &ip2,
						Scenario: &sceanario,
						Type:     &decisionType,
					},
				},
			},
			expectedLines: []parsedLine{
				{
					action:    "add",
					value:     ip1,
					duration:  durationInSeconds,
					sceanario: sceanario,
				},
				{
					action:    "add",
					value:     ip2,
					duration:  durationInSeconds,
					sceanario: sceanario,
				},
			},
		},
		{
			name: "duplicates",
			args: args{
				Decisions: []*models.Decision{
					{
						Duration: &durationWithUnit,
						Value:    &ip1,
						Scenario: &sceanario,
						Type:     &decisionType,
					},
					{
						Duration: &durationWithUnit,
						Value:    &ip1,
						Scenario: &sceanario,
						Type:     &decisionType,
					},
				},
			},
			expectedLines: []parsedLine{
				{
					action:    "add",
					value:     ip1,
					duration:  durationInSeconds,
					sceanario: sceanario,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer cleanup()
			c := &customBouncer{
				path: binaryPath,
			}
			c.ResetCache()
			for _, decision := range tt.args.Decisions {
				err := c.Add(decision)
				if err != nil {
					t.Error(err)
				}
			}
			foundData := parseFile(binaryOutputFile)
			if !reflect.DeepEqual(foundData, tt.expectedLines) {
				t.Errorf("expected=%v, found=%v", tt.expectedLines, foundData)
			}

		})
	}
}

func Test_customBouncer_Delete(t *testing.T) {
	type args struct {
		Decisions []*models.Decision
	}
	tests := []struct {
		name          string
		args          args
		expectedLines []parsedLine
	}{
		{
			name: "simple, single decision",
			args: args{
				Decisions: []*models.Decision{
					{
						Duration: &durationWithUnit,
						Value:    &ip1,
						Scenario: &sceanario,
						Type:     &decisionType,
					},
				},
			},
			expectedLines: []parsedLine{
				{
					action:    "del",
					value:     ip1,
					duration:  durationInSeconds,
					sceanario: sceanario,
				},
			},
		},
		{
			name: "simple, two decisions",
			args: args{
				Decisions: []*models.Decision{
					{
						Duration: &durationWithUnit,
						Value:    &ip1,
						Scenario: &sceanario,
						Type:     &decisionType,
					},
					{
						Duration: &durationWithUnit,
						Value:    &ip2,
						Scenario: &sceanario,
						Type:     &decisionType,
					},
				},
			},
			expectedLines: []parsedLine{
				{
					action:    "del",
					value:     ip1,
					duration:  durationInSeconds,
					sceanario: sceanario,
				},
				{
					action:    "del",
					value:     ip2,
					duration:  durationInSeconds,
					sceanario: sceanario,
				},
			},
		},
		{
			name: "duplicates",
			args: args{
				Decisions: []*models.Decision{
					{
						Duration: &durationWithUnit,
						Value:    &ip1,
						Scenario: &sceanario,
						Type:     &decisionType,
					},
					{
						Duration: &durationWithUnit,
						Value:    &ip1,
						Scenario: &sceanario,
						Type:     &decisionType,
					},
				},
			},
			expectedLines: []parsedLine{
				{
					action:    "del",
					value:     ip1,
					duration:  durationInSeconds,
					sceanario: sceanario,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer cleanup()
			c := &customBouncer{
				path: binaryPath,
			}
			c.ResetCache()
			for _, decision := range tt.args.Decisions {
				err := c.Delete(decision)
				if err != nil {
					t.Error(err)
				}
			}
			foundData := parseFile(binaryOutputFile)
			if !reflect.DeepEqual(foundData, tt.expectedLines) {
				t.Errorf("expected=%v, found=%v", tt.expectedLines, foundData)
			}

		})
	}
}
