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
			name: "DER encoding stringifies to DER keyword",
			e:    distinguishedEncodingRules,
			want: "DER",
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
