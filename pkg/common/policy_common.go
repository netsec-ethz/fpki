package common

// MarshallableDocument is an object that can be marshalled and unmarshalled to and from JSON.
type MarshallableDocument interface {
	Raw() ([]byte, error) // Returns the Raw JSON this object was unmarshaled from or marshals this object into a json objects
	getJSONField() []byte // Returns the Raw JSON this object was unmarshaled from (nil if none).
}

// MarshallableDocumentBase is used to read and write document from and to json files.
// If changing the name of the field, check the file json.go where we introspect for it.
type MarshallableDocumentBase struct {
	JSONField []byte `json:"-"` // omit from JSON (un)marshaling
}

func (o MarshallableDocumentBase) Raw() ([]byte, error) {
	panic("MarshallableDocument interface not fully implemented [missing func Raw() ([]byte, error)]")
}

func (o MarshallableDocumentBase) getJSONField() []byte {
	return o.JSONField
}

func rawTemplate[T MarshallableDocument](o T) ([]byte, error) {
	if o.getJSONField() == nil {
		return ToJSON(&o)
	} else {
		return o.getJSONField(), nil
	}
}

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
