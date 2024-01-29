package common

// MarshallableDocument is an object that can be marshalled and unmarshalled to and from JSON.
type MarshallableDocument interface {
	Raw() []byte // Returns the Raw JSON this object was unmarshaled from (nil if none).
}

// MarshallableDocumentBase is used to read and write document from and to json files.
// If changing the name of the field, check the file json.go where we introspect for it.
type MarshallableDocumentBase struct {
	JSONField []byte `json:"-"` // omit from JSON (un)marshaling
}

// TODO (cyrill): problem is that JSONField is not properly kept up to date (or may not even be set)
// we could either replace it with ToJSON(o) or ensure that it is synchronized
func (o MarshallableDocumentBase) Raw() []byte { return o.JSONField }

// PolicyPart is an interface that is implemented by all objects that are part of the set
// of "policy objects". A policy object is that one that represents functionality of policies
// for a domain, such as PolicyCertificate, a PolicyCertificateSigningRequest, etc.
type PolicyPart interface {
	MarshallableDocument
}

// PolicyPartBase is the common type to all policy documents.
type PolicyPartBase struct {
	MarshallableDocumentBase
	Version int `json:",omitempty"`
}

func (o PolicyPartBase) Equal(x PolicyPartBase) bool {
	// Ignore the RawJSON component, use just the regular fields.
	return o.Version == x.Version
}
