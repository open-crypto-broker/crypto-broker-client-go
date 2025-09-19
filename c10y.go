package cryptobrokerclientgo

// predefined keywords for supported encodings
const (

	// privacyEnhancedMail represents PEM encoding
	privacyEnhancedMail encoding = "PEM"

	// b64 represents base64 encoding
	b64 encoding = "B64"
)

// encoding represents string that is keyword of particular encoding used by library.
type encoding string

func (e encoding) String() string {
	return string(e)
}
