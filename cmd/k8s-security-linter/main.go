package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/DevSpecOps/k8s-security-linter/pkg/engine"
)

type Finding struct {
	File      string `json:"file"`
	Container string `json:"container,omitempty"`
	RuleID    string `json:"rule_id"`
	Message   string `json:"message"`
}

var (
	path   string
	jsonOut bool
)

func main() {
	flag.StringVar(&path, "path", ".", "file or directory to scan")
	flag.BoolVar(&jsonOut, "json", false, "output findings as JSON")
	flag.Parse()

	eng, err := engine.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize Rego engine: %v\n", err)
		os.Exit(1)
	}

	var findings []Finding

	err = filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(p, ".yaml") && !strings.HasSuffix(p, ".yml") {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		findings = append(findings, lintFile(eng, p, data)...)
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "walk error: %v\n", err)
		os.Exit(1)
	}

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(findings)
	} else {
		for _, f := range findings {
			fmt.Printf("❌ %s: %s (rule: %s)\n", f.File, f.Message, f.RuleID)
		}
		if len(findings) == 0 {
			fmt.Println("✅ No security issues found")
		}
	}

	if len(findings) > 0 {
		os.Exit(1)
	}
}

func lintFile(eng *engine.Engine, filePath string, data []byte) []Finding {
	var doc map[string]interface{}
	err := yaml.Unmarshal(data, &doc)
	if err != nil {
		return nil
	}
	kind, _ := doc["kind"].(string)
	var podSpec map[string]interface{}
	switch kind {
	case "Pod":
		if spec, ok := doc["spec"].(map[string]interface{}); ok {
			podSpec = spec
		}
	case "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob":
		if spec, ok := doc["spec"].(map[string]interface{}); ok {
			if template, ok := spec["template"].(map[string]interface{}); ok {
				if ps, ok := template["spec"].(map[string]interface{}); ok {
					podSpec = ps
				}
			}
		}
	}
	if podSpec == nil {
		return nil
	}
	return lintPodSpec(eng, filePath, podSpec)
}

func lintPodSpec(eng *engine.Engine, filePath string, spec map[string]interface{}) []Finding {
	var findings []Finding
	containers, _ := spec["containers"].([]interface{})
	for i, c := range containers {
		cont, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		containerName := fmt.Sprintf("container[%d]", i)
		if name, ok := cont["name"].(string); ok {
			containerName = name
		}
		input := engine.Input{
			Kind:      "Pod",
			PodSpec:   spec,
			Container: cont,
		}
		results, err := eng.Evaluate(input)
		if err != nil {
			continue
		}
		for _, r := range results {
			if !r.Allowed {
				findings = append(findings, Finding{
					File:      filePath,
					Container: containerName,
					RuleID:    r.RuleID,
					Message:   r.Message,
				})
			}
		}
	}
	return findings
}