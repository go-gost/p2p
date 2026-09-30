package host

import "context"

// actionKey is the context key for the caller's action id: a short, opaque
// string that ties a backend log line to the UI action that caused it. p2p
// treats it as a label — it never parses it, stores it, or lets it change
// behaviour — so the seam can log it without trusting it.
type actionKey struct{}

// WithAction returns ctx carrying id, so the seam calls made with it name the
// action in their log line. An empty id is ignored (there is nothing to name),
// so a caller may pass whatever it read without a nil check.
func WithAction(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, actionKey{}, id)
}

// actionOf reads the action id, or "" when ctx carries none.
func actionOf(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	id, _ := ctx.Value(actionKey{}).(string)
	return id
}

// logAction names the caller's action, when ctx carries one, at seam entry. A
// call made without an action logs nothing: the line exists to join a UI action
// to the p2p work it started, so an empty action= on every Listen/Warm/Punch
// would be noise rather than a join. Only Dial (which already took a ctx) and
// the *Context variants call this, so the untouched methods of the
// third-party-facing API keep their old logs exactly.
func (h *Host) logAction(ctx context.Context, call string) {
	if id := actionOf(ctx); id != "" {
		h.log.Info("seam", "call", call, "action", id)
	}
}
