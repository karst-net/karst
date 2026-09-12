// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package policy

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// jsonFieldNames returns t's own json tag names, ignoring options like
// ",omitempty" — the same names JSONSchema's top-level "properties" must list,
// or an editor using the schema would never suggest a field this package
// actually accepts.
func jsonFieldNames(t reflect.Type) []string {
	var names []string
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name != "" && name != "-" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func TestJSONSchemaIsValidJSON(t *testing.T) {
	var decoded map[string]any
	if err := json.Unmarshal([]byte(JSONSchema), &decoded); err != nil {
		t.Fatalf("JSONSchema does not parse: %v", err)
	}
}

// The failure this guards against is silent: an editor using a schema that
// has fallen behind Document does not error, it just never offers the new
// field — indistinguishable from the field not existing until someone reads
// this source to find out otherwise.
func TestJSONSchemaMatchesDocument(t *testing.T) {
	var decoded struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal([]byte(JSONSchema), &decoded); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var schemaFields []string
	for name := range decoded.Properties {
		schemaFields = append(schemaFields, name)
	}
	sort.Strings(schemaFields)

	documentFields := jsonFieldNames(reflect.TypeOf(Document{}))
	if !reflect.DeepEqual(schemaFields, documentFields) {
		t.Fatalf("JSONSchema's properties are %v, but Document's json fields are %v — "+
			"update schema.go to match", schemaFields, documentFields)
	}
}

// Every rule shape (acls, ssh) carries the same three fields Rule/SshRule
// declare, for the same reason as the top-level check.
func TestJSONSchemaRuleShapesMatchTheGoTypes(t *testing.T) {
	for _, tc := range []struct {
		schemaKey string
		goType    reflect.Type
	}{
		{"acls", reflect.TypeOf(Rule{})},
		{"ssh", reflect.TypeOf(SshRule{})},
	} {
		var decoded struct {
			Properties map[string]struct {
				Items struct {
					Properties map[string]json.RawMessage `json:"properties"`
					Required   []string                    `json:"required"`
				} `json:"items"`
			} `json:"properties"`
		}
		if err := json.Unmarshal([]byte(JSONSchema), &decoded); err != nil {
			t.Fatalf("parse: %v", err)
		}
		item := decoded.Properties[tc.schemaKey].Items
		var schemaFields []string
		for name := range item.Properties {
			schemaFields = append(schemaFields, name)
		}
		sort.Strings(schemaFields)
		wantFields := jsonFieldNames(tc.goType)
		if !reflect.DeepEqual(schemaFields, wantFields) {
			t.Fatalf("%s: schema item properties are %v, %s's json fields are %v",
				tc.schemaKey, schemaFields, tc.goType.Name(), wantFields)
		}
		required := append([]string{}, item.Required...)
		sort.Strings(required)
		if !reflect.DeepEqual(required, wantFields) {
			t.Fatalf("%s: schema item requires %v, want every field (%v) required — "+
				"%s has no optional fields", tc.schemaKey, required, wantFields, tc.goType.Name())
		}
	}
}
