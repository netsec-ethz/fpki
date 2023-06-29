package common

// MarshallableDocument is an object that can be marshalled and unmarshalled to and from JSON.
type MarshallableDocument interface {
	Raw() []byte // Returns the Raw JSON this object was unmarshaled from (nil if none).
}

type MarshallableDocumentBase struct {
	RawJSON []byte `json:"-"` // omit from JSON (un)marshaling
}

func (o MarshallableDocumentBase) Raw() []byte { return o.RawJSON }

// PolicyPart is an interface that is implemented by all objects that are part of the set
// of "policy objects". A policy object is that one that represents functionality of policies
// for a domain, such as RPC, RCSR, SPT, SPRT, SP, PSR or Policy.
type PolicyPart interface {
	MarshallableDocument
}

// PolicyPartBase is the common type to all policy documents.
type PolicyPartBase struct {
	MarshallableDocumentBase
	Version int    `json:",omitempty"`
	Issuer  string `json:",omitempty"`
}

func (o PolicyPartBase) Equal(x PolicyPartBase) bool {
	// Ignore the RawJSON component, use just the regular fields.
	return o.Version == x.Version &&
		o.Issuer == x.Issuer
}
