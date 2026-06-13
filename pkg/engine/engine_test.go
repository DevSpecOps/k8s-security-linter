package engine

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEngine(t *testing.T) {
	eng, err := New()
	assert.NoError(t, err)

	tests := []struct {
		name      string
		input     Input
		wantDeny  bool
		wantRuleID string
	}{
		{
			name: "privileged true",
			input: Input{
				Kind: "Pod",
				Container: map[string]interface{}{
					"securityContext": map[string]interface{}{
						"privileged": true,
					},
				},
			},
			wantDeny:  true,
			wantRuleID: "PRIVILEGED",
		},
		{
			name: "runAsNonRoot missing",
			input: Input{
				Container: map[string]interface{}{},
			},
			wantDeny:  true,
			wantRuleID: "RUN_AS_NON_ROOT",
		},
		{
			name: "good container",
			input: Input{
				Container: map[string]interface{}{
					"securityContext": map[string]interface{}{
						"privileged":               false,
						"runAsNonRoot":             true,
						"readOnlyRootFilesystem":   true,
					},
					"resources": map[string]interface{}{
						"limits": map[string]interface{}{
							"memory": "128Mi",
						},
					},
					"image": "nginx:1.21",
				},
			},
			wantDeny: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := eng.Evaluate(tt.input)
			assert.NoError(t, err)
			if tt.wantDeny {
				assert.NotEmpty(t, results)
				found := false
				for _, r := range results {
					if r.RuleID == tt.wantRuleID {
						found = true
						break
					}
				}
				assert.True(t, found, "expected rule %s not found", tt.wantRuleID)
			} else {
				assert.Empty(t, results)
			}
		})
	}
}