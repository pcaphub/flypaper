package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"

	"gopkg.in/yaml.v3"
)

// Set changes scalar values in the config file in place, keeping the file's
// comments and order, and validates the result by loading it before the file
// is replaced. Keys are "section.key" ("select.daily_cap"); a bare key that
// belongs to the select section ("daily_cap") and the top-level "name",
// "region" and "dry_run" are accepted as shorthand. Lists are not handled:
// edit the file for those.
func Set(path string, assignments []string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if doc.Kind == 0 || len(doc.Content) == 0 {
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s: top level is not a mapping", path)
	}

	var changed []string
	for _, a := range assignments {
		k, v, ok := strings.Cut(a, "=")
		if !ok || strings.TrimSpace(k) == "" {
			return nil, fmt.Errorf("want key=value, got %q", a)
		}
		k = resolveKey(strings.TrimSpace(k))
		parts := strings.Split(k, ".")
		node := root
		for _, p := range parts[:len(parts)-1] {
			node = childMapping(node, p)
		}
		leaf := parts[len(parts)-1]
		val := scalarNode(strings.TrimSpace(v))
		if existing := childValue(node, leaf); existing != nil {
			if existing.Kind != yaml.ScalarNode {
				return nil, fmt.Errorf("%s is not a scalar; edit the file for lists", k)
			}
			existing.Value, existing.Tag, existing.Style = val.Value, val.Tag, val.Style
		} else {
			node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: leaf}, val)
		}
		changed = append(changed, k+"="+val.Value)
	}

	var out strings.Builder
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, err
	}
	enc.Close()

	// validate the result the way the service will read it
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*.yaml")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.WriteString(out.String()); err != nil {
		tmp.Close()
		return nil, err
	}
	tmp.Close()
	if _, err := Load(tmpName); err != nil {
		return nil, fmt.Errorf("new config rejected, file unchanged: %w", err)
	}
	// keep the file's mode and owner (root:flypaper 0640 from the installer)
	if st, err := os.Stat(path); err == nil {
		_ = os.Chmod(tmpName, st.Mode().Perm())
		if sys, ok := st.Sys().(*syscall.Stat_t); ok {
			_ = os.Chown(tmpName, int(sys.Uid), int(sys.Gid))
		}
	}
	if err := os.Rename(tmpName, path); err != nil {
		return nil, err
	}
	return changed, nil
}

// selectKeys are the yaml names of the select section, the shorthand set.
var selectKeys = func() map[string]bool {
	m := map[string]bool{}
	t := reflect.TypeOf(Select{})
	for i := 0; i < t.NumField(); i++ {
		if tag := t.Field(i).Tag.Get("yaml"); tag != "" {
			m[strings.Split(tag, ",")[0]] = true
		}
	}
	return m
}()

func resolveKey(k string) string {
	if strings.Contains(k, ".") {
		return k
	}
	if selectKeys[k] {
		return "select." + k
	}
	return k // name, region, dry_run, state_dir, outbox; anything else fails validation
}

func childValue(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func childMapping(m *yaml.Node, key string) *yaml.Node {
	if v := childValue(m, key); v != nil {
		if v.Kind == yaml.MappingNode {
			return v
		}
		// a "select:" line with nothing under it decodes as a null scalar
		v.Kind, v.Tag, v.Value, v.Content = yaml.MappingNode, "!!map", "", nil
		return v
	}
	v := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, v)
	return v
}

func scalarNode(v string) *yaml.Node {
	n := &yaml.Node{Kind: yaml.ScalarNode, Value: v, Tag: "!!str"}
	switch {
	case v == "true" || v == "false":
		n.Tag = "!!bool"
	default:
		if _, err := strconv.ParseInt(v, 10, 64); err == nil {
			n.Tag = "!!int"
		} else if _, err := strconv.ParseFloat(v, 64); err == nil {
			n.Tag = "!!float"
		} else if v == "" || strings.ContainsAny(v, ":#{}[],&*!|>'\"%@`") {
			n.Style = yaml.DoubleQuotedStyle
		}
	}
	return n
}
