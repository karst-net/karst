package context

type ctxKey string

const (
	RequestIDKey ctxKey = "requestID"
	AccountIDKey ctxKey = "accountID"
	RoleKey      ctxKey = "role"
	UserIDKey    ctxKey = "userID"
	PeerIDKey    ctxKey = "peerID"
	UserAgentKey ctxKey = "userAgent"
)
