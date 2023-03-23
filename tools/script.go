package tools

import _ "embed"

//go:embed create_schema.sh
var script string

func CreateSchemaScript() string {
	return script
}
