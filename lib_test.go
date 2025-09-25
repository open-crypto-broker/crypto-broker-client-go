package cryptobrokerclientgo

import (
	"context"
	"testing"
	"time"
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
				return context.WithTimeout(context.Background(), 1*time.Second)
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
