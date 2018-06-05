package test

import (
	"io/ioutil"
	"testing"
)

// WriteTemp writes the provided contents to a temp file with the provided
// prefix and returns the path to the temp file. If there is an error,
// `t.Fatalf` is called to end the test.
func WriteTemp(t *testing.T, contents, prefix string) string {
	tmpFile, err := ioutil.TempFile("", prefix)
	if err != nil {
		t.Fatalf("Unable to create tempfile: %s",
			err.Error())
	}
	err = ioutil.WriteFile(tmpFile.Name(), []byte(contents), 0700)
	if err != nil {
		t.Fatalf("Unable to write tempfile contents: %s",
			err.Error())
	}
	return tmpFile.Name()
}
