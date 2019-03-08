package woodpecker

import (
	"errors"
	"log"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/ct-woodpecker/test"
)

func TestLogConfigValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config LogConfig
		Valid  bool
	}{
		{
			Name:   "Empty log URI",
			Config: LogConfig{},
		},
		{
			Name:   "Invalid log URI",
			Config: LogConfig{URI: "☭"},
		},
		{
			Name:   "Invalid log URI scheme",
			Config: LogConfig{URI: "☮://test"},
		},
		{
			Name:   "Empty log key",
			Config: LogConfig{URI: "http://test.com"},
		},
		{
			Name:   "Start less than zero",
			Config: LogConfig{URI: "https://test.com", Key: "⚷", Start: -1},
		},
		{
			Name:   "Valid log config",
			Config: LogConfig{URI: "https://test.com", Key: "⚷"},
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
	validLogs := []LogConfig{
		{URI: "https://localhost", Key: "⚷", SubmitCert: false, SubmitPreCert: false},
		{URI: "https://remotehost", Key: "⚷", SubmitCert: true, SubmitPreCert: true},
	}

	validConfig := Config{
		DBURI: "file:foobar.db",
		FetchConfig: &STHFetchConfig{
			Interval: "2s",
			Timeout:  "1s",
		},
		SubmitConfig: &CertSubmitConfig{
			Interval:          "60s",
			Timeout:           "2s",
			CertIssuerKeyPath: "⚷",
			CertIssuerPath:    "foo",
		},
		InclusionConfig: &InclusionCheckerConfig{
			Interval:      "120s",
			MaxGetEntries: 128,
		},
		Logs: validLogs,
	}

	testCases := []struct {
		Name        string
		Config      Config
		Valid       bool
		MetricsAddr string
	}{
		{
			Name: "No log configs",
			Config: Config{
				FetchConfig: &STHFetchConfig{
					Interval: "2s",
				},
			},
		},
		{
			Name: "Invalid log",
			Config: Config{
				FetchConfig: &STHFetchConfig{
					Interval: "2s",
				},
				Logs: []LogConfig{{}},
			},
		},
		{
			Name:   "No FetchConfig or SubmitConfig",
			Config: Config{},
		},
		{
			Name: "Invalid STH Fetch Interval",
			Config: Config{
				FetchConfig: &STHFetchConfig{
					Interval: "idk, whenever you feel like it I guess?",
				},
			},
		},
		{
			Name: "Invalid STH Timeout",
			Config: Config{
				FetchConfig: &STHFetchConfig{
					Interval: "2s",
					Timeout:  "when the time is out, time out",
				},
			},
		},
		{
			Name: "Log with submitCert, no SubmitConfig",
			Config: Config{
				Logs: validLogs,
			},
		},
		{
			Name: "Log with submitCert, no cert submit interval",
			Config: Config{
				SubmitConfig: &CertSubmitConfig{
					Interval: "",
				},
				Logs: validLogs,
			},
		},
		{
			Name: "Log with submitCert, invalid cert submit interval",
			Config: Config{
				SubmitConfig: &CertSubmitConfig{
					Interval: "idk, when the mood strikes...",
				},
				Logs: validLogs,
			},
		},
		{
			Name: "Log with submitCert, invalid cert submit timeout",
			Config: Config{
				SubmitConfig: &CertSubmitConfig{
					Interval: "2s",
					Timeout:  "aaaa",
				},
			},
		},
		{
			Name: "Log with submitCert, no cert issuer key path",
			Config: Config{
				SubmitConfig: &CertSubmitConfig{
					Interval:          "2s",
					Timeout:           "2s",
					CertIssuerKeyPath: "",
				},
				Logs: validLogs,
			},
		},
		{
			Name: "Log with submitCert, no cert issuer path",
			Config: Config{
				SubmitConfig: &CertSubmitConfig{
					Interval:          "2s",
					Timeout:           "2s",
					CertIssuerKeyPath: "⚷",
				},
				Logs: validLogs,
			},
		},
		{
			Name: "Log with inclusionCheckerConfig no submitConfig",
			Config: Config{
				InclusionConfig: &InclusionCheckerConfig{
					Interval:      "2s",
					MaxGetEntries: 256,
				},
				Logs: validLogs,
			},
		},
		{
			Name: "Log with inclusionCheckerConfig, invalid interval",
			Config: Config{
				SubmitConfig: &CertSubmitConfig{
					Interval:          "2s",
					Timeout:           "2s",
					CertIssuerKeyPath: "⚷",
					CertIssuerPath:    "foo",
				},
				InclusionConfig: &InclusionCheckerConfig{
					Interval:      "pretty-quickly-i-guess?",
					MaxGetEntries: 256,
				},
				Logs: validLogs,
			},
		},
		{
			Name: "No log with submitCert, non-nil SubmitConfig",
			Config: Config{
				SubmitConfig: &CertSubmitConfig{
					Interval:          "2s",
					Timeout:           "2s",
					CertIssuerKeyPath: "⚷",
					CertIssuerPath:    "foo",
				},
				Logs: []LogConfig{
					{URI: "https://localhost", Key: "⚷", SubmitCert: false, SubmitPreCert: false},
				},
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
	goodConfig := `
{
  "metricsAddr": ":1971",
  "fetchConfig": {
    "interval": "120s",
    "timeout": "2s"
  },
  "submitConfig": {
    "interval": "360s",
    "timeout": "2s",
    "certIssuerKeyPath": "test/issuer.key",
    "certIssuerPath": "test/issuer.pem"
  },
  "logs": [
    {
      "uri": "https://birch.ct.letsencrypt.org/2018",
      "key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElgyN7ptarCAX5krBwDwjhHM+b0xJjCKke+Dfr3GWSbLm3eO7muXRo8FDDdpdiRpnG4NJT0bdzq5YEer4C2eZ+g==",
      "submitCert": true
    }
  ]
}`
	goodConfigFile := test.WriteTemp(t, goodConfig, "good.config")

	badConfig := `{`
	badConfigFile := test.WriteTemp(t, badConfig, "bad.config")

	testCases := []struct {
		Name           string
		Filepath       string
		ExpectedConfig *Config
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
			ExpectedConfig: &Config{
				MetricsAddr: ":1971",
				FetchConfig: &STHFetchConfig{
					Interval: "120s",
					Timeout:  "2s",
				},
				SubmitConfig: &CertSubmitConfig{
					Interval:          "360s",
					Timeout:           "2s",
					CertIssuerKeyPath: "test/issuer.key",
					CertIssuerPath:    "test/issuer.pem",
				},
				Logs: []LogConfig{
					{
						URI:        "https://birch.ct.letsencrypt.org/2018",
						Key:        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElgyN7ptarCAX5krBwDwjhHM+b0xJjCKke+Dfr3GWSbLm3eO7muXRo8FDDdpdiRpnG4NJT0bdzq5YEer4C2eZ+g==",
						SubmitCert: true,
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			conf := Config{}
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

func TestNew(t *testing.T) {
	l := log.New(os.Stdout, "", log.LstdFlags)
	clk := clock.NewFake()
	clk.Set(time.Now())

	// Creating a woodpecker with an invalid config should fail
	_, err := New(Config{}, l, l, clk)
	if err == nil {
		t.Errorf("expected err calling New() with invalid config, got nil")
	}

	logKey := "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElgyN7ptarCAX5krBwDwjhHM+b0xJjCKke+Dfr3GWSbLm3eO7muXRo8FDDdpdiRpnG4NJT0bdzq5YEer4C2eZ+g=="
	logs := []LogConfig{
		{
			URI: "http://log.on",
			Key: logKey,
		},
		{
			URI: "http://log.off",
			Key: logKey,
		},
	}
	// Creating a woodpecker without a submit config should do the expected
	wp, err := New(Config{
		FetchConfig: &STHFetchConfig{
			Interval: "50s",
			Timeout:  "1s",
		},
		Logs: logs,
	}, l, l, clk)
	if err != nil {
		t.Fatalf("unexpected err calling New(): %s\n", err.Error())
	}
	if len(wp.monitors) != len(logs) {
		t.Fatalf("expected %d woodpecker monitors, had %d", len(logs), len(wp.monitors))
	}
	for _, m := range wp.monitors {
		if m.CertSubmitter() {
			t.Errorf("monitor was unexpectedly a cert submitter")
		}
		if !m.STHFetcher() {
			t.Errorf("monitor was not a STH fetcher")
		}
	}

	submitLogs := append(logs, LogConfig{
		URI:        "http://drop.out",
		Key:        logKey,
		SubmitCert: true,
	})

	// Creating a woodpecker without a STH config should do the expected
	wp, err = New(Config{
		SubmitConfig: &CertSubmitConfig{
			Interval:          "20s",
			Timeout:           "2s",
			CertIssuerKeyPath: "../test/issuer.key",
			CertIssuerPath:    "../test/issuer.pem",
		},
		Logs: submitLogs,
	}, l, l, clk)
	if err != nil {
		t.Fatalf("unexpected err calling New(): %s\n", err.Error())
	}
	if len(wp.monitors) != len(submitLogs) {
		t.Fatalf("expected %d woodpecker monitors, had %d", len(logs), len(wp.monitors))
	}
	for _, m := range wp.monitors {
		if m.STHFetcher() {
			t.Errorf("monitor was unexpectedly a STH fetcher")
		}
		if !m.CertSubmitter() {
			t.Errorf("monitor was not a cert submitter")
		}
	}
}
