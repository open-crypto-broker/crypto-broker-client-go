package cryptobrokerclientgo

import "testing"

func TestEncoding_String(t *testing.T) {
	tests := []struct {
		name string
		e    encoding
		want string
	}{
		{
			name: "PEM encoding stringifies to PEM keyword",
			e:    privacyEnhancedMail,
			want: "PEM",
		},
		{
			name: "B64 encoding stringifies to B64 keyword",
			e:    b64,
			want: "B64",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.e.String(); got != tt.want {
				t.Fatalf("encoding.String() = %q, want %q", got, tt.want)
			}
		})
	}
}
