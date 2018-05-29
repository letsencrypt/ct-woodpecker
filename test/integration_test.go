// +build integration

package test

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go"
	"github.com/jmhodges/clock"
	"github.com/letsencrypt/ct-woodpecker/test/cttestsrv"
	"github.com/letsencrypt/ct-woodpecker/woodpecker"
)

// getWoodpeckerMetrics fetches raw prometheus metrics output through the given
// host's `/metrics` HTTP handler. The HTTP response body is returned as
// a string. If there is an error fetching the metrics data this function will
// panic.
func getWoodpeckerMetrics(host string) string {
	url := fmt.Sprintf("%s/metrics", host)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		panic(fmt.Sprintf("Unable to make GET request: %s",
			err.Error()))
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(fmt.Sprintf("Unable to get ct-woodpecker metrics with GET to %q: %s",
			url, err.Error()))
	}
	if resp.StatusCode != http.StatusOK {
		panic(fmt.Sprintf("Unable to get ct-woodpecker metrics with GET to %q: response status %d",
			url, resp.StatusCode))
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(fmt.Sprintf("Unable to read GET response body: %s", err.Error()))
	}

	return string(body)
}

// safeBuffer is a wrapper around a bytes.Buffer that is made safe for
// concurrent access. This is required for making a logger backed by a bytes
// buffer that can be used by a woodpecker instance across multiple goroutines
// without a data race.
type safeBuffer struct {
	b bytes.Buffer
	m sync.RWMutex
}

func (b *safeBuffer) Read(p []byte) (n int, err error) {
	b.m.RLock()
	defer b.m.RUnlock()
	return b.b.Read(p)
}
func (b *safeBuffer) Write(p []byte) (n int, err error) {
	b.m.Lock()
	defer b.m.Unlock()
	return b.b.Write(p)
}

func (b *safeBuffer) String() string {
	b.m.RLock()
	defer b.m.RUnlock()
	return b.b.String()
}

// wodpeckerRun starts a ct-woodpecker monitor with the given configuration. It
// is allowed to run for the given number of fetchIterations. When complete the
// standard out and the raw metrics data from the woodpecker instance are
// returned. If there are any unexpected problems an error is returned instead.
func woodpeckerRun(conf woodpecker.Config, fetchIterations int) (string, string, error) {
	// Create a logger backed by the safeBuffer. The log.Logger type is only safe
	// for concurrent use when the backing buffer is. Using a raw bytes.Buffer
	// with a shared logger will cause data races.
	var out safeBuffer
	logger := log.New(&out, "integration test ", log.LstdFlags)
	clk := clock.Default()

	// Create a Woodpecker with the provided monitoring configuration
	woodpecker, err := woodpecker.New(conf, logger, clk)
	if err != nil {
		return "", "", err
	}

	// Calculate the fetchInterval duration from the configuration
	fetchInterval, err := time.ParseDuration(conf.STHFetchInterval)
	if err != nil {
		return "", "", err
	}

	// Start the monitoring process
	woodpecker.Run()

	// Sleep for the right amount of time based on the fetchInterval and the
	// requested number of iterations
	time.Sleep(fetchInterval * time.Duration(fetchIterations))

	// Collect metrics from the woodpecker instance while it is still running
	metricsData := getWoodpeckerMetrics("http://localhost:1971")

	woodpecker.Stop()

	return out.String(), metricsData, nil
}

// testServers creates & starts a number of CT test servers based on the
// provided personalities. The servers are returned so that the caller can
// cleanly shut them down when required.
func testServers(personalities []cttestsrv.Personality) []*cttestsrv.IntegrationSrv {
	var servers []*cttestsrv.IntegrationSrv
	for _, p := range personalities {
		logger := log.New(os.Stdout, fmt.Sprintf("ct-test-srv %q ", p.Addr), log.LstdFlags)
		srv, err := cttestsrv.NewServer(p, logger)
		if err != nil {
			logger.Fatal(err)
		}
		servers = append(servers, srv)
		srv.Run()
	}

	return servers
}

// defaultPersonalities returns hardcoded Personality data suitable for running
// two test CT log servers, one on :4500, one on :4501.
func defaultPersonalities() []cttestsrv.Personality {
	return []cttestsrv.Personality{
		cttestsrv.Personality{
			Addr:    ":4500",
			PrivKey: "MHcCAQEEIOCtGlGt/WT7471dOHdfBg43uJWJoZDkZAQjWfTitcVNoAoGCCqGSM49AwEHoUQDQgAEYggOxPnPkzKBIhTacSYoIfnSL2jPugcbUKx83vFMvk5gKAz/AGe87w20riuPwEGn229hKVbEKHFB61NIqNHC3Q==",
			LatencySchedule: []float64{
				0.1,
				0.5,
			},
		},
		cttestsrv.Personality{
			Addr:    ":4501",
			PrivKey: "MHcCAQEEIJSCFDYXt2xCIxv+G8BCzGdUsFIQDWEjxfJDfnn9JB5loAoGCCqGSM49AwEHoUQDQgAEKtnFevaXV/kB8dmhCNZHmxKVLcHX1plaAsY9LrKilhYxdmQZiu36LvAvosTsqMVqRK9a96nC8VaxAdaHUbM8EA==",
			LatencySchedule: []float64{
				0.5,
				0.1,
			},
		},
	}
}

// TestFetchSTHSuccess tests that a ct-woodpecker instance correctly checks the
// STH of mock CT servers configured for success.
func TestFetchSTHSuccess(t *testing.T) {
	// root is an encoded SHA256 hash that we can jam into mock STHs
	var root ct.SHA256Hash
	_ = root.FromBase64String("ZVWlmKuutzCIAIjNuVW0kYrk69eqWbNtLX86CBMVneg=")
	now := time.Now()

	// Create and start some CT test servers with the default personalities
	testServers := testServers(defaultPersonalities())

	// Generate a mock STH for each of the CT test servers
	mockSTHs := make([]*ct.SignedTreeHead, len(testServers))
	for i, srv := range testServers {
		// Offset each log's fake STH into the past by 1 hour + the log index
		offset := -time.Duration(i+1) * time.Hour
		ts := now.Add(offset).UnixNano() / int64(time.Millisecond)

		// Generate a new mock STH for the log at the calculated timestamp offset
		mockSTHs[i] = &ct.SignedTreeHead{
			TreeSize:       0xC0FFEE,
			SHA256RootHash: root,
			Timestamp:      uint64(ts),
		}
		// Set the mock STH
		srv.SetSTH(mockSTHs[i])
	}

	// Create a CT woodpecker configuration that fetches the STH of the two test logs every 5s
	fetchInterval := 5 * time.Second
	config := woodpecker.Config{
		STHFetchInterval: fetchInterval.String(),
		MetricsAddr:      ":1971",
	}
	logConfigs := make([]woodpecker.LogConfig, len(testServers))
	for i, srv := range testServers {
		logConfigs[i] = woodpecker.LogConfig{
			URI: fmt.Sprintf("http://localhost%s", srv.Addr),
			Key: srv.PubKey,
		}
	}
	config.Logs = logConfigs

	// Run ct-woodpecker for 1 full STH fetch iteration using the above config
	iterations := 2
	stdout, metricsData, err := woodpeckerRun(config, iterations)
	if err != nil {
		t.Fatalf("woodpecker run failed: %s", err.Error())
	}

	// There should be no STH fetch errors in the stdout
	if strings.Contains(stdout, "Error fetching STH") {
		t.Errorf("Unexpected STH fetch error in ct-woodpecker stdout: \n%s\n", stdout)
	}

	// Check that each of the test servers was handled correctly by the monitor.
	for i, srv := range testServers {
		// Check how many times each log's STH was fetched by the monitor
		sthFetches := srv.STHFetches()
		// We expect each log had its STH fetched twice: Once at startup, and once
		// for each of the iterations elapsed.
		if sthFetches != int64(iterations+1) {
			t.Errorf("Expected %d sth fetches for log %q, got %d",
				(iterations + 1), srv.Addr, sthFetches)
		}

		// Check that each log has the correct STH timestamp in the metrics output
		expectedTS := float64(mockSTHs[i].Timestamp)
		expectedTimestampLine := fmt.Sprintf(`sth_timestamp{uri="http://localhost%s"} %g`,
			srv.Addr, expectedTS)
		if !strings.Contains(metricsData, expectedTimestampLine) {
			t.Errorf("Could not find expected metrics line %q in metrics output: \n%s\n",
				expectedTimestampLine, metricsData)
		}

		// Check that each log has the expected STH latency count
		expectedLatencyCount := iterations
		expectedLatencyCountLine := fmt.Sprintf(`sth_latency_count{uri="http://localhost%s"} %d`,
			srv.Addr, expectedLatencyCount)
		if !strings.Contains(metricsData, expectedLatencyCountLine) {
			t.Errorf("Could not find expected metrics line %q in metrics output: \n%s\n",
				expectedLatencyCountLine, metricsData)
		}

		// Check that each log has the expected STH age in the metrics output
		expectedAge := int((time.Duration(i+1)*time.Hour + fetchInterval*time.Duration(iterations-1)).Seconds())
		// Use a regex to match just the integer portion of the age float to allow
		// for some fractional inprecision
		expectedAgeRegex := regexp.MustCompile(
			fmt.Sprintf(`sth_age{uri="http://localhost%s"} %d.[\d]+`,
				srv.Addr, expectedAge))
		if !expectedAgeRegex.MatchString(metricsData) {
			t.Errorf("Could not find expected metrics line %q in metrics output: \n%s\n",
				expectedAgeRegex.String(), metricsData)
		}
	}
}
