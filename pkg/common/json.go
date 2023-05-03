package common

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"reflect"

	"github.com/google/trillian"
	trilliantypes "github.com/google/trillian/types"
)

type serializableObjectBase struct {
	O       any  // actual object to Marshal/Unmarshal
	skipRaw bool // flag controlling JSON copying into PolicyObjectBase.Raw
}

func ToJSON(obj any) ([]byte, error) {
	if _, ok := obj.(serializableObjectBase); !ok {
		obj = serializableObjectBase{
			O: obj,
		}
	}
	return json.Marshal(obj)
}

func FromJSON(data []byte, opts ...FromJSONModifier) (any, error) {
	var base serializableObjectBase
	for _, mod := range opts {
		mod(&base)
	}
	err := json.Unmarshal(data, &base)
	return base.O, err
}

type FromJSONModifier func(*serializableObjectBase)

// WithSkipCopyJSONIntoPolicyObjects avoids copying the raw JSON into each one of the
// objects that aggregate a PolicyObjectBase (RPC, SP, etc).
func WithSkipCopyJSONIntoPolicyObjects(o *serializableObjectBase) {
	o.skipRaw = true
}

func (o serializableObjectBase) MarshalJSON() ([]byte, error) {
	T, O, err := o.marshalJSON(o.O)
	if err != nil {
		return nil, err
	}

	tmp := struct {
		T string
		O json.RawMessage
	}{
		T: T,
		O: O,
	}
	return json.Marshal(tmp)
}

// marshalJSON returns two components matching T and O: the Type (string) and the payload of O.
func (*serializableObjectBase) marshalJSON(obj any) (string, []byte, error) {
	var T string
	switch obj.(type) {
	case RCSR:
		T = "rcsr"
	case RPC:
		T = "rpc"
	case PCRevocation:
		T = "rev"
	case SP:
		T = "sp"
	case SPT:
		T = "spt"
	case SPRT:
		T = "sprt"
	case PSR:
		T = "psr"
	case trillian.Proof:
		T = "trillian.Proof"
	case trilliantypes.LogRootV1:
		T = "logrootv1"
	default:
		valOf := reflect.ValueOf(obj)
		switch valOf.Kind() {
		case reflect.Pointer:
			// Dereference and convert to "any".
			T, O, err := (*serializableObjectBase)(nil).marshalJSON(valOf.Elem().Interface())
			return fmt.Sprintf("*%s", T), O, err
		case reflect.Slice:
			// A slice. Serialize each item and also serialize the slice itself.
			children := make([]json.RawMessage, valOf.Len())
			for i := 0; i < len(children); i++ {
				v := valOf.Index(i).Interface()
				b, err := ToJSON(v)
				if err != nil {
					return "", nil, fmt.Errorf("marshaling slice, element %d failed: %w", i, err)
				}
				children[i] = b
			}
			data, err := json.Marshal(children)
			return "[]", data, err
		default:
			return "", nil, fmt.Errorf("unknown type %T", obj)
		}
	}
	data, err := json.Marshal(obj)
	return T, data, err
}

func (o *serializableObjectBase) UnmarshalJSON(data []byte) error {
	tmp := struct {
		T string
		O json.RawMessage
	}{}

	err := json.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}
	// Parse the T,O that we received.
	wasPtr := false
	ok, obj, err := o.unmarshalTypeObject(tmp.T, tmp.O)
	if !ok && len(tmp.T) > 0 && tmp.T[0] == '*' {
		// It looks like a pointer, try again just once.
		wasPtr = true
		tmp.T = tmp.T[1:] // Remove the *
		ok, obj, err = o.unmarshalTypeObject(tmp.T, tmp.O)
	}

	// Almost everything is done now. We should 1. do a obj = &obj and 2. copy the raw JSON
	// into the Raw field of the structure.
	shouldCopyJSON := !o.skipRaw && reflect.ValueOf(obj).Kind() != reflect.Slice
	if ok && (wasPtr || shouldCopyJSON) { // skip if no JSON copy and it wasn't a pointer
		// Until here, obj is never a pointer. Convert obj to a pointer to obj.
		objPtr := reflect.New(reflect.TypeOf(obj)) // new pointer of T
		objPtr.Elem().Set(reflect.ValueOf(obj))    // assign original object
		obj = objPtr.Interface()                   // obj is now a pointer to the original

		// If we should copy JSON to Raw:
		if shouldCopyJSON {
			// Find out if the object is a pointer to a PolicyObjectBase like structure.
			base := reflect.Indirect(reflect.ValueOf(obj)).FieldByName("PolicyObjectBase")
			if base != (reflect.Value{}) {
				// It is a PolicyObjectBase like object. Check the Raw field (should always be true).
				if raw := base.FieldByName("RawJSON"); raw != (reflect.Value{}) {
					// Set its value to the JSON data.
					raw.Set(reflect.ValueOf(data))
				} else {
					// This should never happen, and the next line should ensure it:
					_ = PolicyObjectBase{}.RawJSON
					// But terminate the control flow anyways with a panic.
					panic("logic error: structure PolicyObjectBase has lost its Raw member")
				}
			}
		}

		// If the object was not a pointer, and it had been converted to a pointer, revert.
		if !wasPtr {
			obj = reflect.Indirect(reflect.ValueOf(obj)).Interface()
		}
	}

	o.O = obj
	return err
}

// unmarshalTypeObject returns true if the function understood the type in T, and the object with
// the specific type represented by T.
func (o *serializableObjectBase) unmarshalTypeObject(T string, data []byte) (bool, any, error) {
	var obj any
	var err error
	switch T {
	case "[]":
		// There is a slice of objects beneath this object.
		var tmp []json.RawMessage
		err = json.Unmarshal(data, &tmp)
		if err != nil {
			err = fmt.Errorf("unmarshaling slice, object doesn't seem to be a slice: %w", err)
		}
		if err == nil {
			list := make([]any, len(tmp))
			obj = list
			for i, objData := range tmp {
				// Is this an embedded SerializableObjectBase?
				tmp := serializableObjectBase{
					skipRaw: o.skipRaw,
				}
				err = json.Unmarshal(objData, &tmp)
				if err != nil {
					err = fmt.Errorf("unmarshaling slice, element at %d failed: %w", i, err)
					break
				}
				list[i] = tmp.O
			}
		}
	case "rcsr":
		obj, err = inflateObj[RCSR](data)
	case "rpc":
		obj, err = inflateObj[RPC](data)
	case "rev":
		obj, err = inflateObj[PCRevocation](data)
	case "sp":
		obj, err = inflateObj[SP](data)
	case "spt":
		obj, err = inflateObj[SPT](data)
	case "sprt":
		obj, err = inflateObj[SPRT](data)
	case "psr":
		obj, err = inflateObj[PSR](data)
	case "trillian.Proof":
		obj, err = inflateObj[trillian.Proof](data)
	case "logrootv1":
		obj, err = inflateObj[trilliantypes.LogRootV1](data)
	default:
		err = fmt.Errorf("unknown type represented by \"%s\"", T)
		obj = nil
	}
	return obj != nil, obj, err
}

func inflateObj[T any](data []byte) (any, error) {
	var tmp T
	err := json.Unmarshal(data, &tmp)

	return tmp, err
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
