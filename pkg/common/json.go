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
	O any
}

func ToJSON(obj any) ([]byte, error) {
	if _, ok := obj.(serializableObjectBase); !ok {
		obj = serializableObjectBase{
			O: obj,
		}
	}
	return json.Marshal(obj)
}

func FromJSON(data []byte) (any, error) {
	var base serializableObjectBase
	err := json.Unmarshal(data, &base)
	return base.O, err
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
		switch valOf.Type().Kind() {
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
	ok, obj, err := unmarshalTypeObject(tmp.T, tmp.O)
	if !ok {
		if len(tmp.T) > 0 && tmp.T[0] == '*' {
			// Pointer, try again just once.
			tmp.T = tmp.T[1:]
			_, obj, err = unmarshalTypeObject(tmp.T, tmp.O)
			// Now convert to a pointer to the original object.
			objPtr := reflect.New(reflect.TypeOf(obj))
			objPtr.Elem().Set(reflect.ValueOf(obj)) // assign original object
			obj = objPtr.Interface()
		}
	}
	o.O = obj
	return err
}

// unmarshalTypeObject returns true if the function understood the type in T, and the object with
// the specific type represented by T.
func unmarshalTypeObject(T string, data []byte) (bool, any, error) {
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
				tmp := serializableObjectBase{}
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

//
//
//
//
//
//
//
//

// func JSONToPoI(poiBytes []byte) ([]*trillian.Proof, error) {
// 	po, err := FromJSON(poiBytes)
// 	if err != nil {
// 		return nil, fmt.Errorf("JsonBytesToPoI | Unmarshal | %w", err)
// 	}
// 	result, ok := po.([]*trillian.Proof)
// 	if !ok {
// 		return nil, fmt.Errorf("JsonFileToPoI | object is %T", po)
// 	}
// 	return result, nil
// }

// // JSONToLogRoot: Bytes -> log root in json
// func JSONToLogRoot(logRootBytes []byte) (*trilliantypes.LogRootV1, error) {
// 	po, err := FromJSON(logRootBytes)
// 	if err != nil {
// 		return nil, fmt.Errorf("JsonBytesToLogRoot | Unmarshal | %w", err)
// 	}
// 	result, ok := po.(*trilliantypes.LogRootV1)
// 	if !ok {
// 		return nil, fmt.Errorf("JsonFileToLogRoot | object is %T", po)
// 	}
// 	return result, nil
// }

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
