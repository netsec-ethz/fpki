package common

// MarshallableDocument is an object that can be marshalled and unmarshalled to and from JSON.
type MarshallableDocument interface {
	Raw() []byte // Returns the Raw JSON this object was unmarshaled from (nil if none).
}

// PolicyPart is an interface that is implemented by all objects that are part of the set
// of "policy objects". A policy object is that one that represents functionality of policies
// for a domain, such as RPC, RCSR, SPT, SPRT, SP, PSR or Policy.
type PolicyPart interface {
	MarshallableDocument
	Version() int
	Issuer() string
}

// PolicyPartBase is the common type to all policy documents.
type PolicyPartBase struct {
	RawJSON    []byte `json:"-"` // omit from JSON (un)marshaling
	RawVersion int    `json:"Version,omitempty"`
	RawIssuer  string `json:"Issuer,omitempty"`
}

func (o PolicyPartBase) Raw() []byte    { return o.RawJSON }
func (o PolicyPartBase) Version() int   { return o.RawVersion }
func (o PolicyPartBase) Issuer() string { return o.RawIssuer }

func (o PolicyPartBase) Equal(x PolicyPartBase) bool {
	// Ignore the RawJSON component, use just the regular fields.
	return o.RawVersion == x.RawVersion &&
		o.RawIssuer == x.RawIssuer
}
