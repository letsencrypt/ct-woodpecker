package main

import (
	"errors"
	"io/ioutil"
	"reflect"
	"testing"
)

func TestLogConfigValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config logConfig
		Valid  bool
	}{
		{
			Name:   "Empty log URI",
			Config: logConfig{},
		},
		{
			Name:   "Invalid log URI",
			Config: logConfig{URI: "☭"},
		},
		{
			Name:   "Invalid log URI scheme",
			Config: logConfig{URI: "☮://test"},
		},
		{
			Name:   "Empty log key",
			Config: logConfig{URI: "http://test.com"},
		},
		{
			Name:   "Valid log config",
			Config: logConfig{URI: "https://test.com", Key: "⚷"},
			Valid:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			if err := tc.Config.Valid(); err != nil && tc.Valid {
				t.Errorf("Expected log config %#v to be valid, had error: %s",
					tc.Config, err)
			} else if err == nil && !tc.Valid {
				t.Errorf("Expected log config %#v to be invalid, had nil error",
					tc.Config)
			}
		})
	}
}

func TestConfigValid(t *testing.T) {

	validConfig := config{
		STHFetchInterval: "2s",
		Logs: []logConfig{
			logConfig{URI: "https://localhost", Key: "⚷"},
		},
	}

	testCases := []struct {
		Name        string
		Config      config
		Valid       bool
		MetricsAddr string
	}{
		{
			Name: "Invalid STH Fetch Interval",
			Config: config{
				STHFetchInterval: "idk, whenever you feel like it I guess?",
			},
		},
		{
			Name: "No log configs",
			Config: config{
				STHFetchInterval: "2s",
			},
		},
		{
			Name: "Invalid log",
			Config: config{
				STHFetchInterval: "2s",
				Logs:             []logConfig{{}},
			},
		},
		{
			Name:   "Valid config",
			Config: validConfig,
			Valid:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			if err := tc.Config.Valid(); err != nil && tc.Valid {
				t.Errorf("Expected config %#v to be valid, had error: %s", tc.Config, err)
			} else if err == nil && !tc.Valid {
				t.Errorf("Expected config %#v to be invalid, had nil error",
					tc.Config)
			}
		})
	}

	// Also test that a Config without a metrics address gets the default address
	// assigned in `Valid()`
	validConfig.MetricsAddr = ""
	if err := validConfig.Valid(); err != nil {
		t.Error("validConfig was considered invalid with an empty MetricsAddr")
	}
	if validConfig.MetricsAddr != ":1971" {
		t.Errorf("validConfig has MetricsAddr %q after .Valid(), expected %q",
			validConfig.MetricsAddr, ":1971")
	}
}

func TestConfigLoad(t *testing.T) {
	writeTemp := func(content, prefix string) string {
		tmpFile, err := ioutil.TempFile("", prefix)
		if err != nil {
			t.Fatalf("Unable to create tempfile: %s",
				err.Error())
		}
		err = ioutil.WriteFile(tmpFile.Name(), []byte(content), 0700)
		if err != nil {
			t.Fatalf("Unable to write tempfile contents: %s",
				err.Error())
		}
		return tmpFile.Name()
	}
	goodConfig := `
{
  "sthFetchInterval": "120s",
  "metricsAddr": ":1971",
  "logs": [
    {
      "uri": "https://birch.ct.letsencrypt.org/2018",
      "key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElgyN7ptarCAX5krBwDwjhHM+b0xJjCKke+Dfr3GWSbLm3eO7muXRo8FDDdpdiRpnG4NJT0bdzq5YEer4C2eZ+g=="
    }
  ]
}`
	goodConfigFile := writeTemp(goodConfig, "good.config")

	badConfig := `{`
	badConfigFile := writeTemp(badConfig, "bad.config")

	testCases := []struct {
		Name           string
		Filepath       string
		ExpectedConfig *config
		Error          error
	}{
		{
			Name:  "Empty filepath",
			Error: errors.New("Config file path must not be empty"),
		},
		{
			Name:     "Bad config filepath",
			Filepath: badConfigFile,
			Error:    errors.New("unexpected end of JSON input"),
		},
		{
			Name:     "Good config",
			Filepath: goodConfigFile,
			ExpectedConfig: &config{
				STHFetchInterval: "120s",
				MetricsAddr:      ":1971",
				Logs: []logConfig{
					logConfig{
						URI: "https://birch.ct.letsencrypt.org/2018",
						Key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElgyN7ptarCAX5krBwDwjhHM+b0xJjCKke+Dfr3GWSbLm3eO7muXRo8FDDdpdiRpnG4NJT0bdzq5YEer4C2eZ+g==",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			conf := config{}
			err := conf.Load(tc.Filepath)
			if err != nil {
				if tc.Error == nil {
					t.Errorf("Expected nil error, got %#v", err)
				} else if err.Error() != tc.Error.Error() {
					t.Errorf("Expected error %q, got %q", err.Error(), tc.Error.Error())
				}
			} else {
				if equal := reflect.DeepEqual(conf, *tc.ExpectedConfig); !equal {
					t.Errorf("Expected config %#v, got %#v", *tc.ExpectedConfig, conf)
				}
			}
		})
	}
}
