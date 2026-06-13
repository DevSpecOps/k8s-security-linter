package engine

import (
	"context"
	_ "embed"
	"fmt"

	"github.com/open-policy-agent/opa/rego"
)

//go:embed rules.rego
var policyFile []byte

type Engine struct {
	preparedEval rego.PreparedEvalQuery
}

type Input struct {
	Kind      string                 `json:"kind"`
	PodSpec   map[string]interface{} `json:"podSpec"`
	Container map[string]interface{} `json:"container"`
}

type Result struct {
	Allowed bool   `json:"allowed"`
	RuleID  string `json:"rule_id,omitempty"`
	Message string `json:"message,omitempty"`
}

func New() (*Engine, error) {
	query := "data.k8s.deny"
	r := rego.New(
		rego.Query(query),
		rego.Module("rules.rego", string(policyFile)),
	)
	ctx := context.Background()
	prepared, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare rego: %w", err)
	}
	return &Engine{preparedEval: prepared}, nil
}

func (e *Engine) Evaluate(input Input) ([]Result, error) {
	ctx := context.Background()
	results, err := e.preparedEval.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, err
	}
	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return nil, nil
	}
	val := results[0].Expressions[0].Value
	denyList, ok := val.([]interface{})
	if !ok {
		return nil, nil
	}
	var out []Result
	for _, d := range denyList {
		obj, ok := d.(map[string]interface{})
		if !ok {
			continue
		}
		r := Result{}
		if allowed, ok := obj["allowed"].(bool); ok {
			r.Allowed = allowed
		}
		if ruleID, ok := obj["rule_id"].(string); ok {
			r.RuleID = ruleID
		}
		if msg, ok := obj["message"].(string); ok {
			r.Message = msg
		}
		out = append(out, r)
	}
	return out, nil
}