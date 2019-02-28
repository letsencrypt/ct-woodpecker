package monitor

import (
	"errors"
	"fmt"
	"testing"

	ctClient "github.com/google/certificate-transparency-go/client"
)

func TestWrapRspErr(t *testing.T) {
	normalErr := errors.New("just a normal error reporting for duty")

	rspErr := ctClient.RspError{
		Err:        normalErr,
		StatusCode: 999,
		Body:       []byte("This is the body of a ctClient.RspError"),
	}

	testCases := []struct {
		Name        string
		InputErr    error
		ExpectedErr error
	}{
		{
			Name:        "nil input err",
			InputErr:    nil,
			ExpectedErr: nil,
		},
		{
			Name:        "non-RespError input err",
			InputErr:    normalErr,
			ExpectedErr: normalErr,
		},
		{
			Name:     "rspError input err",
			InputErr: rspErr,
			ExpectedErr: fmt.Errorf("%s HTTP Response Status: %d HTTP Response Body: %q",
				normalErr.Error(), rspErr.StatusCode, string(rspErr.Body)),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			actualErr := wrapRspErr(tc.InputErr)
			if tc.ExpectedErr == nil && actualErr != nil {
				t.Fatalf("Expected err to be nil, was %#v", actualErr)
			} else if tc.ExpectedErr != nil && actualErr == nil {
				t.Fatalf("Expected err to be %#v, was nil", tc.ExpectedErr)
			} else if tc.ExpectedErr != nil {
				actual := actualErr.Error()
				expected := tc.ExpectedErr.Error()
				if actual != expected {
					t.Errorf("Expected err %q got %q", expected, actual)
				}
			}
		})
	}
}
