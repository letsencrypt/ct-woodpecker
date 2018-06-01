// +build integration

package test

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
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

// wodpeckerRun starts a ct-woodpecker monitor with the given configuration. It
// is allowed to run for the given duration. When complete the standard out and
// the raw metrics data from the woodpecker instance are returned. If there are
// any unexpected problems an error is returned instead.
func woodpeckerRun(conf woodpecker.Config, duration time.Duration) (string, string, error) {
	// Create a logger backed by the SafeBuffer. The log.Logger type is only safe
	// for concurrent use when the backing buffer is. Using a raw bytes.Buffer
	// with a shared logger will cause data races.
	var out SafeBuffer
	logger := log.New(&out, "integration test ", log.LstdFlags)
	clk := clock.Default()

	// Create a Woodpecker with the provided monitoring configuration
	woodpecker, err := woodpecker.New(conf, logger, clk)
	if err != nil {
		return "", "", err
	}

	// Start the monitoring process
	woodpecker.Run()

	// Sleep for the requested amount of time
	time.Sleep(duration)

	// Collect metrics from the woodpecker instance while it is still running
	metricsData := getWoodpeckerMetrics("http://localhost:1971")

	woodpecker.Stop()

	return out.String(), metricsData, nil
}

// testServers creates & starts a number of CT test servers based on the
// provided personalities. The servers and a cleanup function are returned to
// the caller. The cleanup function can be used to gracefully stop the challenge
// servers.
func testServers(personalities []cttestsrv.Personality) ([]*cttestsrv.IntegrationSrv, func()) {
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

	return servers, func() {
		for _, srv := range servers {
			srv.Shutdown()
		}
	}
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
	testServers, cleanup := testServers(defaultPersonalities())
	defer cleanup()

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

	// Create a CT woodpecker configuration that fetches the STH of the two test logs every 100ms
	fetchInterval := 100 * time.Millisecond
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

	// Sleep for the right amount of time based on the fetchInterval and the
	// number of iterations.
	iterations := 2
	padding := time.Millisecond * 20
	duration := fetchInterval*time.Duration(iterations) + padding

	// Run ct-woodpecker for the specified number of iterations using the above
	// config
	stdout, metricsData, err := woodpeckerRun(config, duration)
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
		// We expect a certain minimum number of fetches based on the iterations. If
		// there were *more* fetches that's OK, the test probably ran a little long.
		if sthFetches < int64(iterations+1) {
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

		// Check that each log has the minimum expected STH latency count. If there
		// were more latency submissions than expected that's OK, the test probably
		// ran a little long.
		expectedLatencyCountRegexp := regexp.MustCompile(
			fmt.Sprintf(`sth_latency_count{uri="http://localhost%s"} ([\d]+)`,
				srv.Addr))
		expectedLatencyCount := iterations + 1
		if matches := expectedLatencyCountRegexp.FindStringSubmatch(metricsData); len(matches) < 2 {
			t.Errorf("Could not find expected sth_latency_count line in metrics output: \n%s\n",
				metricsData)
		} else if latencyCount, err := strconv.Atoi(matches[1]); err != nil {
			t.Errorf("sth_latency_count for log %s had non-numeric value", srv.Addr)
		} else if latencyCount < expectedLatencyCount {
			t.Errorf("expected sth_latency_count of %d for log %s, found %d", expectedLatencyCount, srv.Addr, latencyCount)
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

func TestCertSubmissionSuccess(t *testing.T) {
	// root is an encoded SHA256 hash that we can jam into mock STHs
	var root ct.SHA256Hash
	_ = root.FromBase64String("ZVWlmKuutzCIAIjNuVW0kYrk69eqWbNtLX86CBMVneg=")

	// Create and start some CT test servers with the default personalities
	testServers, cleanup := testServers(defaultPersonalities())
	defer cleanup()

	ts := time.Now().UnixNano() / int64(time.Millisecond)
	// Set a mock STH for each log
	for _, srv := range testServers {
		srv.SetSTH(&ct.SignedTreeHead{
			TreeSize:       0xC0FFEE,
			SHA256RootHash: root,
			Timestamp:      uint64(ts),
		})
	}

	// Create a woodpecker Config that submits a cert every 100ms
	submitInterval := 100 * time.Millisecond
	config := woodpecker.Config{
		MetricsAddr:        ":1971",
		STHFetchInterval:   time.Hour.String(),
		CertSubmitInterval: submitInterval.String(),
		CertIssuer:         "../test/issuer.pem",
		CertIssuerKey:      "../test/issuer.key",
	}
	logConfigs := make([]woodpecker.LogConfig, len(testServers))
	for i, srv := range testServers {
		logConfigs[i] = woodpecker.LogConfig{
			URI: fmt.Sprintf("http://localhost%s", srv.Addr),
			Key: srv.PubKey,
		}
	}
	config.Logs = logConfigs

	// Run ct-woodpecker for the specified number of iterations using the above
	// config
	iterations := 2
	padding := time.Millisecond * 50
	duration := submitInterval*time.Duration(iterations) + padding
	stdout, metricsData, err := woodpeckerRun(config, duration)
	if err != nil {
		t.Fatalf("woodpecker run failed: %s", err.Error())
	}

	// There should be no cert submission errors in the stdout
	if strings.Contains(stdout, "Error submitting certificate") {
		t.Errorf("Unexpected cert submission error in ct-woodpecker stdout: \n%s\n", stdout)
	}

	// There should be no cert_submit_failures lines in the metrics data
	if strings.Contains(metricsData, `cert_submit_failures`) {
		t.Errorf("Unexpected cert_submit_failures metric in metricsData: \n%s\n", metricsData)
	}

	for _, srv := range testServers {
		// Check that each log received the minimum expected number of chain
		// submissions
		expectedSubmissionCount := int64(iterations + 1)
		submissionCount := srv.Submissions()
		if submissionCount < expectedSubmissionCount {
			t.Errorf("Expected test server %s to have recieved >= %d add-chain calls, had %d",
				srv.Addr, expectedSubmissionCount, submissionCount)
		}

		// Check that each log has the minimum expected cert_submit_successes in metrics output
		expectedSuccessRegexp := regexp.MustCompile(
			fmt.Sprintf(`cert_submit_successes{uri="http://localhost%s"} ([\d]+)`,
				srv.Addr))
		expectedSuccess := iterations + 1
		if matches := expectedSuccessRegexp.FindStringSubmatch(metricsData); len(matches) < 2 {
			t.Errorf("Could not find expected cert_submit_successes line in metrics output: \n%s\n",
				metricsData)
		} else if successCount, err := strconv.Atoi(matches[1]); err != nil {
			t.Errorf("cert_submit_successes for log %s had non-numeric value", srv.Addr)
		} else if successCount < expectedSuccess {
			t.Errorf("expected cert_submit_lsuccesses of %d for log %s, found %d",
				expectedSuccess, srv.Addr, successCount)
		}

		// Check that each log has the minimum expected cert_submit_latency_count.
		// If there were more latency submissions than expected that's OK, the test
		// probably ran a little long.
		expectedLatencyCountRegexp := regexp.MustCompile(
			fmt.Sprintf(`cert_submit_latency_count{uri="http://localhost%s"} ([\d]+)`,
				srv.Addr))
		expectedLatencyCount := iterations + 1
		if matches := expectedLatencyCountRegexp.FindStringSubmatch(metricsData); len(matches) < 2 {
			t.Errorf("Could not find expected cert_submit_latency_count line in metrics output: \n%s\n",
				metricsData)
		} else if latencyCount, err := strconv.Atoi(matches[1]); err != nil {
			t.Errorf("cert_submit_latency_count for log %s had non-numeric value", srv.Addr)
		} else if latencyCount < expectedLatencyCount {
			t.Errorf("expected cert_submit_latency_count of %d for log %s, found %d",
				expectedLatencyCount, srv.Addr, latencyCount)
		}
	}
}
