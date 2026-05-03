package upstox

import "encoding/json"

// wrapDataEnvelope wraps v into the {"data": v} request envelope used by
// service.upstox.com endpoints (steps 2-5).
func wrapDataEnvelope(v any) []byte {
	b, _ := json.Marshal(struct {
		Data any `json:"data"`
	}{Data: v})
	return b
}

// parseErrorBody attempts to extract a human-readable error message from
// an Upstox error response. It tries Format A (api.upstox.com:
// `{"status":"error","errors":[...]}`) first, then Format B
// (service.upstox.com: `{"success":false,"error":{...}}`). Returns:
//
//   - message: the extracted message ("" if both formats fail).
//   - raw:     the full decoded body as a map[string]any (nil if the body
//     isn't valid JSON).
//   - ok:      true when the body decoded as JSON (regardless of which
//     envelope shape matched).
func parseErrorBody(body []byte) (message string, raw map[string]any, ok bool) {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return "", nil, false
	}
	raw = m
	ok = true

	// Format A: top-level "errors" array.
	if errs, _ := m["errors"].([]any); len(errs) > 0 {
		if first, _ := errs[0].(map[string]any); first != nil {
			if msg, _ := first["message"].(string); msg != "" {
				return msg, raw, ok
			}
		}
	}
	// Format A alternative: top-level "error" object.
	if e, _ := m["error"].(map[string]any); e != nil {
		if msg, _ := e["message"].(string); msg != "" {
			return msg, raw, ok
		}
	}

	return "", raw, ok
}
