package common

// MarshallableDocument is an object that can be marshalled and unmarshalled to and from JSON.
type MarshallableDocument interface {
	Raw() []byte // Returns the Raw JSON this object was unmarshaled from (nil if none).
}

// PolicyDocument is an interface that is implemented by all objects that are part of the set
// of "policy objects". A policy object is that one that represents functionality of policies
// for a domain, such as RPC, RCSR, SPT, SPRT, SP, PSR or Policy.
type PolicyDocument interface {
	MarshallableDocument
	Subject() string
}

// PolicyObjectBase is the common type to all policy documents.
type PolicyObjectBase struct {
	RawJSON    []byte `json:"-"` // omit from JSON (un)marshaling
	RawSubject string `json:"Subject,omitempty"`
}

func (o PolicyObjectBase) Raw() []byte     { return o.RawJSON }
func (o PolicyObjectBase) Subject() string { return o.RawSubject }
