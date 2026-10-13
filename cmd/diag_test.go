package cmd

import (
	"testing"
)

func TestCheckStrictExit(t *testing.T) {
	tests := []struct {
		name           string
		checksExecuted int
		strict         bool
		wantErr        bool
		wantCode       int
	}{
		{
			name:           "strict false, zero checks",
			checksExecuted: 0,
			strict:         false,
			wantErr:        false,
		},
		{
			name:           "strict false, some checks",
			checksExecuted: 5,
			strict:         false,
			wantErr:        false,
		},
		{
			name:           "strict true, zero checks",
			checksExecuted: 0,
			strict:         true,
			wantErr:        true,
			wantCode:       3,
		},
		{
			name:           "strict true, some checks",
			checksExecuted: 5,
			strict:         true,
			wantErr:        false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkStrictExit(tc.checksExecuted, tc.strict)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				exitErr, ok := err.(*ExitError)
				if !ok {
					t.Fatalf("expected *ExitError, got %T", err)
				}
				if exitErr.ExitCode() != tc.wantCode {
					t.Errorf("exit code = %d, want %d", exitErr.ExitCode(), tc.wantCode)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}
