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

var (
	// root is an encoded SHA256 hash that we can jam into mock STHs
	root ct.SHA256Hash
)

func init() {
	_ = root.FromBase64String("ZVWlmKuutzCIAIjNuVW0kYrk69eqWbNtLX86CBMVneg=")
}

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
	woodpecker, err := woodpecker.New(conf, logger, logger, clk)
	if err != nil {
		return "", "", err
	}

	// Start the monitoring process
	woodpecker.Run()
	defer woodpecker.Stop()

	// Sleep for the requested amount of time
	time.Sleep(duration)

	// Collect metrics from the woodpecker instance while it is still running
	return out.String(), getWoodpeckerMetrics("http://localhost:1971"), nil
}

// testServers creates & starts a number of CT test servers based on the
// provided personalities. The servers and a cleanup function are returned to
// the caller. The cleanup function can be used to gracefully stop the challenge
// servers.
func testServers(personalities []cttestsrv.Personality) ([]*cttestsrv.IntegrationSrv, func()) {
	var servers []*cttestsrv.IntegrationSrv
	fmt.Printf("Starting %d test servers\n", len(personalities))
	for _, p := range personalities {
		logger := log.New(os.Stdout, fmt.Sprintf("ct-test-srv %q ", p.Addr), log.LstdFlags)
		srv, err := cttestsrv.NewServer(p, logger)
		if err != nil {
			logger.Fatal(err)
		}
		servers = append(servers, srv)
		srv.Run()

		// Wait for a little bit for the test server to come up before proceeding
		ready := false
		for i := 0; i < 5; i++ {
			_, err := http.Get(fmt.Sprintf("http://localhost%s", p.Addr))
			if err == nil {
				ready = true
				break
			}
			time.Sleep(time.Millisecond * 100)
		}
		if !ready {
			panic(fmt.Sprintf("Timed out waiting for ct-testserver %s\n", p.Addr))
		}
	}
	fmt.Printf("Test servers are ready\n")

	return servers, func() {
		for _, srv := range servers {
			srv.Shutdown()
		}
	}
}

const (
	logKeyA = "MHcCAQEEIOCtGlGt/WT7471dOHdfBg43uJWJoZDkZAQjWfTitcVNoAoGCCqGSM49AwEHoUQDQgAEYggOxPnPkzKBIhTacSYoIfnSL2jPugcbUKx83vFMvk5gKAz/AGe87w20riuPwEGn229hKVbEKHFB61NIqNHC3Q=="
	logKeyB = "MHcCAQEEIJSCFDYXt2xCIxv+G8BCzGdUsFIQDWEjxfJDfnn9JB5loAoGCCqGSM49AwEHoUQDQgAEKtnFevaXV/kB8dmhCNZHmxKVLcHX1plaAsY9LrKilhYxdmQZiu36LvAvosTsqMVqRK9a96nC8VaxAdaHUbM8EA=="
)

var (
	personalityA = cttestsrv.Personality{
		Addr:    ":4500",
		PrivKey: logKeyA,
		LatencySchedule: []float64{
			0.00,
		},
	}
	personalityB = cttestsrv.Personality{
		Addr:    ":4501",
		PrivKey: logKeyB,
		LatencySchedule: []float64{
			0.00,
		},
	}
	// defaultPersonalities is hardcoded Personality data suitable for running
	// two low-latency test CT log servers, one on :4500, one on :4501.
	defaultPersonalities = []cttestsrv.Personality{personalityA, personalityB}
)

// TestFetchSTHSuccess tests that a ct-woodpecker instance correctly checks the
// STH of mock CT servers configured for success.
func TestFetchSTHSuccess(t *testing.T) {
	// Create and start some CT test servers with the default personalities
	testServers, cleanup := testServers(defaultPersonalities)
	defer cleanup()

	now := time.Now()

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

	// Create a CT woodpecker configuration that fetches the STH of the two test logs
	fetchInterval := time.Millisecond * 100
	config := woodpecker.Config{
		MetricsAddr: ":1971",
		FetchConfig: &woodpecker.STHFetchConfig{
			Interval: fetchInterval.String(),
			Timeout:  "200ms",
		},
	}
	logConfigs := make([]woodpecker.LogConfig, len(testServers))
	for i, srv := range testServers {
		logConfigs[i] = woodpecker.LogConfig{
			URI: fmt.Sprintf("http://localhost%s", srv.Addr),
			Key: srv.PubKey,
		}
	}
	config.Logs = logConfigs

	stdout, metricsData, err := woodpeckerRun(config, time.Second)
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

		// There should have been at least two STH fetches: One at startup, and one
		// after the fetchInterval has elapsed.
		if sthFetches < 2 {
			t.Errorf("Expected 2 sth fetches for log %q, got %d",
				srv.Addr, sthFetches)
		}

		// There should be at least two latency observations for each log
		expectedLatencyCountRegexp := regexp.MustCompile(
			fmt.Sprintf(`sth_latency_count{uri="http://localhost%s"} ([\d]+)`,
				srv.Addr))
		if matches := expectedLatencyCountRegexp.FindStringSubmatch(metricsData); len(matches) < 2 {
			t.Errorf("Could not find expected sth_latency_count line in metrics output: \n%s\n",
				metricsData)
		} else if latencyCount, err := strconv.Atoi(matches[1]); err != nil {
			t.Errorf("sth_latency_count for log %s had non-numeric value", srv.Addr)
		} else if latencyCount < 2 {
			t.Errorf("expected sth_latency_count > 2 for log %s, found %d", srv.Addr, latencyCount)
		}

		// Check that each log has the correct STH timestamp in the metrics output
		expectedTS := float64(mockSTHs[i].Timestamp)
		expectedTimestampLine := fmt.Sprintf(`sth_timestamp{uri="http://localhost%s"} %g`,
			srv.Addr, expectedTS)
		if !strings.Contains(metricsData, expectedTimestampLine) {
			t.Errorf("Could not find expected metrics line %q in metrics output: \n%s\n",
				expectedTimestampLine, metricsData)
		}

		// Check that each log has a minimum expected STH age in the metrics output
		expectedMinAge := float64((time.Duration(i+1) * time.Hour).Seconds())
		// Find the floating point age in the metrics output with a regex
		expectedMinAgeRegex := regexp.MustCompile(
			fmt.Sprintf(`sth_age{uri="http://localhost%s"} ((?:[0-9]*[.])?[0-9]+)`, srv.Addr))
		if matches := expectedMinAgeRegex.FindStringSubmatch(metricsData); len(matches) != 2 {
			t.Errorf("Could not find expected metrics line %q in metrics output: \n%s\n",
				expectedMinAgeRegex.String(), metricsData)
		} else if age, err := strconv.ParseFloat(matches[1], 64); err != nil {
			t.Errorf("sth_age metric for log %s had value %s and was not a floating point value: %s", srv.Addr, matches[1], err)
		} else if age < expectedMinAge {
			t.Errorf("sth_age metric for log %s had value %f expected > %f", srv.Addr, age, expectedMinAge)
		}
	}
}

func TestCertSubmissionSuccess(t *testing.T) {
	// Create and start some CT test servers with the default personalities
	testServers, cleanup := testServers(defaultPersonalities)
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

	// Create a woodpecker Config that submits a precert and a cert to the
	// monitored log
	submitInterval := time.Millisecond * 200
	config := woodpecker.Config{
		MetricsAddr: ":1971",
		SubmitConfig: &woodpecker.CertSubmitConfig{
			Interval:          submitInterval.String(),
			Timeout:           "500ms",
			CertIssuerPath:    "../test/issuer.pem",
			CertIssuerKeyPath: "../test/issuer.key",
		},
	}
	logConfigs := make([]woodpecker.LogConfig, len(testServers))
	for i, srv := range testServers {
		logConfigs[i] = woodpecker.LogConfig{
			URI:           fmt.Sprintf("http://localhost%s", srv.Addr),
			Key:           srv.PubKey,
			SubmitCert:    true,
			SubmitPreCert: true,
		}
	}
	config.Logs = logConfigs

	stdout, metricsData, err := woodpeckerRun(config, time.Second)
	if err != nil {
		t.Fatalf("woodpecker run failed: %s", err.Error())
	}

	// There should be no cert submission errors in the stdout
	if strings.Contains(stdout, "Error submitting certificate") {
		t.Errorf("Unexpected cert submission error in ct-woodpecker stdout: \n%s\n", stdout)
	}

	// There should be no cert_submit_results with status="fail" in the metrics data for precerts or certs
	if strings.Contains(metricsData, `cert_submit_results{precert="true",status="fail"`) {
		t.Errorf("Unexpected cert_submit_results with fail status in metricsData: \n%s\n", metricsData)
	}
	if strings.Contains(metricsData, `cert_submit_results{precert="false",status="fail"`) {
		t.Errorf("Unexpected cert_submit_results with fail status in metricsData: \n%s\n", metricsData)
	}

	assertResultsStat := func(precert bool, status, addr string, expected int, metricsData string) {
		statRegexp := regexp.MustCompile(
			fmt.Sprintf(`cert_submit_results{duplicate="false",precert="%s",status="%s",uri="http://localhost%s"} ([\d]+)`,
				strconv.FormatBool(precert), status, addr))
		if matches := statRegexp.FindStringSubmatch(metricsData); len(matches) < 2 {
			t.Errorf("Could not find expected cert_submit_results line in metrics output: \n%s\n",
				metricsData)
		} else if count, err := strconv.Atoi(matches[1]); err != nil {
			t.Errorf("cert_submit_results count for log %s had non-numeric value", addr)
		} else if count < expected {
			t.Errorf("expected cert_submit_results count of >= %d for log %s, found %d",
				expected, addr, count)
		}
	}

	assertLatencyCount := func(precert bool, addr string, expected int, metricsData string) {
		statRegexp := regexp.MustCompile(
			fmt.Sprintf(`cert_submit_latency_count{precert="%s",uri="http://localhost%s"} ([\d]+)`,
				strconv.FormatBool(precert), addr))
		if matches := statRegexp.FindStringSubmatch(metricsData); len(matches) < 2 {
			t.Errorf("Could not find expected cert_submit_latency_count line in metrics output: \n%s\n",
				metricsData)
		} else if latencyCount, err := strconv.Atoi(matches[1]); err != nil {
			t.Errorf("cert_submit_latency_count for log %s had non-numeric value", addr)
		} else if latencyCount < expected {
			t.Errorf("expected cert_submit_latency_count of >= %d for log %s, found %d",
				expected, addr, latencyCount)
		}
	}

	for _, srv := range testServers {
		// Check that each log received the minimum expected number of chain
		// submissions. There should have been 1 submission at startup and at least
		// 1 more submission after the submit interval elapsed.
		submissionCount := srv.Submissions()
		if submissionCount < 2 {
			t.Errorf("Expected test server %s to have received >= 2 add-chain calls, had %d",
				srv.Addr, submissionCount)
		}

		// Check that each log has the minimum expected cert_submit_results with
		// status=ok in metrics output for both precerts and cert.
		assertResultsStat(true, "ok", srv.Addr, 2, metricsData)
		assertResultsStat(false, "ok", srv.Addr, 2, metricsData)

		// Check that each log has the minimum expected cert_submit_latency_count
		// for both precerts and certs.
		assertLatencyCount(true, srv.Addr, 2, metricsData)
		assertLatencyCount(false, srv.Addr, 2, metricsData)
	}
}

// TestCoordinatedSTHOmission tests that fetching the STH of a slow log does not
// affect the number of STH fetches performed to avoid skewing metrics.
func TestCoordinatedSTHOmission(t *testing.T) {
	// Set up a personality that will have a large latency schedule
	slowAddr := ":4500"
	slowPersonalityA := cttestsrv.Personality{
		Addr:    slowAddr,
		PrivKey: logKeyA,
		LatencySchedule: []float64{
			5.0,
		},
	}
	// Use the slow personality and a regular fast personality together. This will
	// let us test that the fast personality server isn't affected by the slow
	// one.
	slowAndFastPersonalities := []cttestsrv.Personality{slowPersonalityA, personalityB}
	testServers, cleanup := testServers(slowAndFastPersonalities)
	defer cleanup()

	// Generate a mock STH for each of the CT test servers
	mockSTHs := make([]*ct.SignedTreeHead, len(testServers))
	for i, srv := range testServers {
		ts := time.Now().Add(-time.Hour).UnixNano() / int64(time.Millisecond)
		mockSTHs[i] = &ct.SignedTreeHead{
			TreeSize:       0xC0FFEE,
			SHA256RootHash: root,
			Timestamp:      uint64(ts),
		}
		srv.SetSTH(mockSTHs[i])
	}

	// Create a CT woodpecker configuration that fetches the STH of the two test
	// logs. The fetch config should specify an interval that is *lower* than the
	// latency schedule from slowPersonalityA.
	fetchInterval := time.Millisecond * 200
	config := woodpecker.Config{
		MetricsAddr: ":1971",
		FetchConfig: &woodpecker.STHFetchConfig{
			Interval: fetchInterval.String(),
			Timeout:  "500ms",
		},
	}
	logConfigs := make([]woodpecker.LogConfig, len(testServers))
	for i, srv := range testServers {
		logConfigs[i] = woodpecker.LogConfig{
			URI: fmt.Sprintf("http://localhost%s", srv.Addr),
			Key: srv.PubKey,
		}
	}
	config.Logs = logConfigs

	stdout, _, err := woodpeckerRun(config, time.Second)
	if err != nil {
		t.Fatalf("woodpecker run failed: %s", err.Error())
	}

	slowCount, fastCount := 0, 0
	for _, srv := range testServers {
		expectedFetchLine := fmt.Sprintf(`sthFetcher http://localhost%s : Fetching STH`,
			srv.Addr)
		fetchLinesCount := strings.Count(stdout, expectedFetchLine)

		if srv.Addr == slowAddr {
			slowCount = fetchLinesCount
		} else {
			fastCount = fetchLinesCount
		}

		// We expect that each log has two or more attempted STH fetches in the
		// stdout: one from startup and one after the fetch interval has elapsed
		if fetchLinesCount < 2 {
			fmt.Printf("Stdout: \n%s\n", stdout)
			t.Errorf("Expected 2 reported sth fetches in stdout for log %q, got %d",
				srv.Addr, fetchLinesCount)
		}
	}

	// We also expect both the slow and fast logs had the same number of STH fetches
	if slowCount != fastCount {
		t.Errorf("Expected same number of STH fetches for slow server and fast server. "+
			"Saw %d fetches for the slow server and %d for the fast",
			slowCount, fastCount)
	}
}

// TestCoordinatedCertOmissions tests that submitting precerts/certs to a slow
// log does not affect the number of submissions done to avoid skewing metrics.
func TestCoordinatedCertOmission(t *testing.T) {
	// Set up a personality that will have a large latency schedule
	slowAddr := ":4500"
	slowPersonalityA := cttestsrv.Personality{
		Addr:    slowAddr,
		PrivKey: logKeyA,
		LatencySchedule: []float64{
			5.0,
		},
	}
	// Use the slow personality and a regular fast personality together. This will
	// let us test that the fast personality server isn't affected by the slow
	// one.
	slowAndFastPersonalities := []cttestsrv.Personality{slowPersonalityA, personalityB}
	testServers, cleanup := testServers(slowAndFastPersonalities)
	defer cleanup()

	// Create a CT woodpecker configuration that submits certificates to the two
	// logs. The submit config should specify an interval that is *lower* than the
	// latency schedule from slowPersonalityA.
	submitInterval := time.Millisecond * 200
	config := woodpecker.Config{
		MetricsAddr: ":1971",
		SubmitConfig: &woodpecker.CertSubmitConfig{
			Interval:          submitInterval.String(),
			Timeout:           "500ms",
			CertIssuerPath:    "../test/issuer.pem",
			CertIssuerKeyPath: "../test/issuer.key",
		},
	}
	logConfigs := make([]woodpecker.LogConfig, len(testServers))
	for i, srv := range testServers {
		logConfigs[i] = woodpecker.LogConfig{
			URI:           fmt.Sprintf("http://localhost%s", srv.Addr),
			Key:           srv.PubKey,
			SubmitPreCert: true,
			SubmitCert:    true,
		}
	}
	config.Logs = logConfigs

	stdout, _, err := woodpeckerRun(config, time.Second)
	if err != nil {
		t.Fatalf("woodpecker run failed: %s", err.Error())
	}

	slowCount, fastCount := 0, 0

	// We expect at least one cert and one precert submission per log (plus 1 at
	// startup). If the latency of the submit operation slows down the number of
	// submissions made monitoring will be skewed!
	for _, srv := range testServers {
		expectedPrecertLine := fmt.Sprintf(
			`certSubmitter http://localhost%s : Submitting precertificate`,
			srv.Addr)
		precertLineCount := strings.Count(stdout, expectedPrecertLine)
		if precertLineCount < 2 {
			t.Errorf("Expected 2 precertificate submissions in stdout for log %q, got %d",
				srv.Addr, precertLineCount)
		}

		expectedCertLine := fmt.Sprintf(
			`certSubmitter http://localhost%s : Submitting certificate`,
			srv.Addr)
		certLineCount := strings.Count(stdout, expectedCertLine)
		if certLineCount < 2 {
			t.Errorf("Expected 2 certificate submissions in stdout for log %q, got %d",
				srv.Addr, certLineCount)
		}

		if certLineCount != precertLineCount {
			t.Errorf("Expected same number of precerts and certs for log %q, got %d precerts and %d certs",
				srv.Addr, precertLineCount, certLineCount)
		}

		// NOTE(@cpu): We can avoid saving the precert line count because we already
		// checked that it is equal to the cert line count.
		if srv.Addr == slowAddr {
			slowCount = certLineCount
		} else {
			fastCount = certLineCount
		}
	}

	// We also expect both the slow and fast logs had the same number of submissions
	if slowCount != fastCount {
		t.Errorf("Expected same number of cert submissions for slow server and fast server. "+
			"Saw %d submissions for the slow server and %d for the fast",
			slowCount, fastCount)
	}
}
