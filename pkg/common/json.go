package common

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"reflect"

	"github.com/google/trillian"
	trilliantypes "github.com/google/trillian/types"
)

func JSONToPoI(poiBytes []byte) ([]*trillian.Proof, error) {
	po, err := FromJSON(poiBytes)
	if err != nil {
		return nil, fmt.Errorf("JsonBytesToPoI | Unmarshal | %w", err)
	}
	result, ok := po.([]*trillian.Proof)
	if !ok {
		return nil, fmt.Errorf("JsonFileToPoI | object is %T", po)
	}
	return result, nil
}

// JSONToLogRoot: Bytes -> log root in json
func JSONToLogRoot(logRootBytes []byte) (*trilliantypes.LogRootV1, error) {
	po, err := FromJSON(logRootBytes)
	if err != nil {
		return nil, fmt.Errorf("JsonBytesToLogRoot | Unmarshal | %w", err)
	}
	result, ok := po.(*trilliantypes.LogRootV1)
	if !ok {
		return nil, fmt.Errorf("JsonFileToLogRoot | object is %T", po)
	}
	return result, nil
}

// JsonFileToRPC: read json files and unmarshal it to Root Policy Certificate
func JsonFileToRPC(filePath string) (*RPC, error) {
	po, err := FromJSONFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("JsonFileToRPC | Unmarshal | %w", err)
	}

	o, ok := po.(*RPC)
	if !ok {
		return nil, fmt.Errorf("JsonFileToRPC | object is %T", po)
	}
	return o, nil
}

// JsonFileToSPT: read json files and unmarshal it to Signed Policy Timestamp
func JsonFileToSPT(filePath string) (*SPT, error) {
	po, err := FromJSONFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("JsonFileToSPT | Unmarshal | %w", err)
	}

	o, ok := po.(*SPT)
	if !ok {
		return nil, fmt.Errorf("JsonFileToSPT | object is %T", po)
	}
	return o, nil
}

// JsonFileToProof: read json files and unmarshal it to trillian proof
func JsonFileToProof(filePath string) (*trillian.Proof, error) {
	po, err := FromJSONFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("JsonFileToProof | Unmarshal | %w", err)
	}

	o, ok := po.(*trillian.Proof)
	if !ok {
		return nil, fmt.Errorf("JsonFileToProof | object is %T", po)
	}
	return o, nil
}

// JsonFileToSTH: read json files and unmarshal it to Signed Tree Head
func JsonFileToSTH(filePath string) (*trilliantypes.LogRootV1, error) {
	po, err := FromJSONFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("JsonFileToSTH | Unmarshal | %w", err)
	}

	o, ok := po.(*trilliantypes.LogRootV1)
	if !ok {
		return nil, fmt.Errorf("JsonFileToSTH | object is %T", po)
	}
	return o, nil
}

// JsonFileToSTH reads a json file and unmarshals it to a Signed Policy.
func JsonFileToSP(filePath string) (*SP, error) {
	po, err := FromJSONFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("JsonFileToSP | Unmarshal | %w", err)
	}

	o, ok := po.(*SP)
	if !ok {
		err = fmt.Errorf("JsonFileToSP | object is %T", po)
	}
	return o, err
}

func ToJSON(o any) ([]byte, error) {
	r := struct {
		T string
		O any
	}{
		O: o,
	}
	// Find the internal type of the object to marshal.
	switch o := o.(type) {
	case *RCSR:
		r.T = "rcsr"
	case *RPC:
		r.T = "rpc"
	case *PCRevocation:
		r.T = "pcrevocation"
	case *SPT:
		r.T = "spt"
	case *SPRT:
		r.T = "sprt"
	case *SP:
		r.T = "sp"
	case *PSR:
		r.T = "psr"
	case *trillian.Proof:
		r.T = "trillian.Proof"
	case []*trillian.Proof:
		r.T = "[]trillian.Proof"
	case *trilliantypes.LogRootV1:
		r.T = "LogRootV1"
	case listOfMarshallable:
		r.T = "[]"
	default:
		if t := reflect.TypeOf(o); t.Kind() == reflect.Slice {
			// If slice, try to serialize all elements inside, then write its type as slice.
			s := reflect.ValueOf(o)
			listOfAny := make([]any, s.Len())
			for i := 0; i < len(listOfAny); i++ {
				listOfAny[i] = s.Index(i).Interface()
			}
			b, err := ToJSON(listOfMarshallable{
				List: listOfAny,
			})
			return b, err
		}
		return nil, fmt.Errorf("unrecognized type %T", o)
	}

	// Now Marshal the wrapper.
	d, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("wrapping marshalling of object: %w", err)
	}
	return d, nil
}

func FromJSON(data []byte) (any, error) {
	// Get only the type.
	typeOnly := struct {
		T string
	}{}
	if err := json.Unmarshal(data, &typeOnly); err != nil {
		return nil, fmt.Errorf("obtaining the wrapping type: %w", err)
	}

	switch typeOnly.T {
	case "rcsr":
		typeAndValue := struct {
			T string
			O *RCSR
		}{}
		if err := json.Unmarshal(data, &typeAndValue); err != nil {
			return nil, fmt.Errorf("unmarshalling internal type: %w", err)
		}
		return typeAndValue.O, nil
	case "rpc":
		typeAndValue := struct {
			T string
			O *RPC
		}{}
		if err := json.Unmarshal(data, &typeAndValue); err != nil {
			return nil, fmt.Errorf("unmarshalling internal type: %w", err)
		}
		return typeAndValue.O, nil
	case "spt":
		typeAndValue := struct {
			T string
			O *SPT
		}{}
		if err := json.Unmarshal(data, &typeAndValue); err != nil {
			return nil, fmt.Errorf("unmarshalling internal type: %w", err)
		}
		return typeAndValue.O, nil
	case "sprt":
		typeAndValue := struct {
			T string
			O *SPRT
		}{}
		if err := json.Unmarshal(data, &typeAndValue); err != nil {
			return nil, fmt.Errorf("unmarshalling internal type: %w", err)
		}
		return typeAndValue.O, nil
	case "sp":
		typeAndValue := struct {
			T string
			O *SP
		}{}
		if err := json.Unmarshal(data, &typeAndValue); err != nil {
			return nil, fmt.Errorf("unmarshalling internal type: %w", err)
		}
		return typeAndValue.O, nil
	case "psr":
		typeAndValue := struct {
			T string
			O *PSR
		}{}
		if err := json.Unmarshal(data, &typeAndValue); err != nil {
			return nil, fmt.Errorf("unmarshalling internal type: %w", err)
		}
		return typeAndValue.O, nil
	case "trillian.Proof":
		typeAndValue := struct {
			T string
			O *trillian.Proof
		}{}
		if err := json.Unmarshal(data, &typeAndValue); err != nil {
			return nil, fmt.Errorf("unmarshalling internal type: %w", err)
		}
		return typeAndValue.O, nil
	case "[]trillian.Proof":
		typeAndValue := struct {
			T string
			O []*trillian.Proof
		}{}
		if err := json.Unmarshal(data, &typeAndValue); err != nil {
			return nil, fmt.Errorf("unmarshalling internal type: %w", err)
		}
		return typeAndValue.O, nil
	case "LogRootV1":
		typeAndValue := struct {
			T string
			O *trilliantypes.LogRootV1
		}{}
		if err := json.Unmarshal(data, &typeAndValue); err != nil {
			return nil, fmt.Errorf("unmarshalling internal type: %w", err)
		}
		return typeAndValue.O, nil
	case "[]":
		// This is a special case. We have received a list of "things" that should be
		// deserializable again with FromJSON. Deserialize this object of type listOfMarshallable
		// and return all its internal objects
		typeAndValue := struct {
			T string
			O listOfMarshallable
		}{}
		if err := json.Unmarshal(data, &typeAndValue); err != nil {
			return nil, fmt.Errorf("unmarshalling internal type: %w", err)
		}
		return typeAndValue.O.List, nil
	default:
		return nil, fmt.Errorf("unmarshalling internal type: bad type \"%s\"", typeOnly.T)
	}
}

// ToJSONFile serializes any supported type to a file, using JSON.
func ToJSONFile(s any, filePath string) error {
	bytes, err := ToJSON(s)
	if err != nil {
		return fmt.Errorf("JsonStructToFile | ToJSON | %w", err)
	}

	err = ioutil.WriteFile(filePath, bytes, 0644)
	if err != nil {
		return fmt.Errorf("JsonStructToFile | WriteFile | %w", err)
	}
	return nil
}

func FromJSONFile(filePath string) (any, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	return FromJSON(data)
}

// marshallableObject is used only on deserialization. A list of these objects is read from the
// JSON and should be parsed using FromJSON(). See listOfMarshallable.UnmarshalJSON.
type marshallableObject struct {
	O any
}

func (o marshallableObject) MarshalJSON() ([]byte, error) {
	return ToJSON(o.O)
}

func (o *marshallableObject) UnmarshalJSON(b []byte) error {
	obj, err := FromJSON(b)
	o.O = obj
	return err
}

// listOfMarshallable is used to allow (de)serialization (from)to JSON. When a list of our
// types is to be serialized, a list of these objects is created instead (see ToJSON).
type listOfMarshallable struct {
	List []any
}

// MarshalJSON serializes to JSON a list of objects than can be convertible to JSON via
// the method ToJSON.
func (l listOfMarshallable) MarshalJSON() ([]byte, error) {
	payloads := make([][]byte, len(l.List))
	for i, e := range l.List {
		b, err := ToJSON(e)
		if err != nil {
			return nil, fmt.Errorf("cannot marshal list to JSON, elem at %d failed with error: %s",
				i, err)
		}
		payloads[i] = b
	}
	// this list in JSON consists in the type and then the ToJSON elements.
	payload := []byte(`{"List":[`)
	for _, p := range payloads {
		payload = append(payload, p...)
		payload = append(payload, []byte(`,`)...)
	}
	// Remove last ","
	payload = payload[:len(payload)-1]
	// Close list and close object itself.
	payload = append(payload, []byte(`]}`)...)

	return payload, nil
}

func (l *listOfMarshallable) UnmarshalJSON(b []byte) error {
	// Deserialize an object with a "List" field that will use FromJSON for its elements.
	tempObject := struct {
		List []marshallableObject
	}{}
	err := json.Unmarshal(b, &tempObject)
	if err != nil {
		return err
	}
	// Take the list with wrapped objects and unwrap them to this list.
	l.List = make([]any, len(tempObject.List))
	for i, o := range tempObject.List {
		l.List[i] = o.O
	}
	return nil
}
