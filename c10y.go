package cryptobrokerclientgo

// predefined keywords for supported encodings
const (

	// privacyEnhancedMail represents PEM encoding
	privacyEnhancedMail encoding = "PEM"

	// distinguishedEncodingRules represents DER encoding
	distinguishedEncodingRules encoding = "DER"
)

// encoding represents string that is keyword of particular encoding used by library.
type encoding string

func (e encoding) String() string {
	return string(e)
}
