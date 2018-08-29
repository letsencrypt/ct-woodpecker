package monitor

import (
	"fmt"
	"log"

	ctClient "github.com/google/certificate-transparency-go/client"
	"github.com/jmhodges/clock"
)

// wrapRspErr takes an errors as input and if it is a ctClient.RspError
// instance it is returned in a wrapped form that prints the HTTP response
// status and body in the error message. All other error types are passed
// through unmodified.
func wrapRspErr(err error) error {
	if err == nil {
		return nil
	}

	// If it is an RspError instance, wrap it
	if rspErr, ok := err.(ctClient.RspError); ok {
		return fmt.Errorf("%s HTTP Response Status: %d HTTP Response Body: %q",
			rspErr.Err, rspErr.StatusCode, string(rspErr.Body))
	}

	// If it wasn't an RspError instance, return as-is
	return err
}

type monitorCheck struct {
	logURI            string
	logID             int64
	maximumMergeDelay int
	label             string
	clk               clock.Clock
	stdout            *log.Logger
	stderr            *log.Logger
}

func (mc monitorCheck) logErrorf(format string, args ...interface{}) {
	line := fmt.Sprintf(format, args...)
	mc.logError(line)
}

func (mc monitorCheck) logError(msg string) {
	mc.stderr.Print("[ERROR]", " ", mc.label, " ", mc.logURI, " : ", msg)
}

func (mc monitorCheck) logf(format string, args ...interface{}) {
	line := fmt.Sprintf(format, args...)
	mc.log(line)
}

func (mc monitorCheck) log(msg string) {
	mc.stdout.Print(mc.label, " ", mc.logURI, " : ", msg)
}
