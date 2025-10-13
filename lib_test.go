package cryptobrokerclientgo

import (
	"context"
	"testing"
)

func TestNewLibrary(t *testing.T) {
	tests := []struct {
		name         string
		ctxGenerator func() (context.Context, context.CancelFunc)
		wantErr      bool
	}{
		{
			name: "NewLibrary() fails if it cannot connect to server in context window",
			ctxGenerator: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel() // manually cancel context so that provided context is already done
				return ctx, cancel
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := tt.ctxGenerator()
			defer cancel()

			_, err := NewLibrary(ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewLibrary() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
