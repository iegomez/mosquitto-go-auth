package constants

// Mosquitto 1.5 introduces a new acc, MOSQ_ACL_SUBSCRIBE. Kept the names, so don't mind the linter.
// In almost any case, subscribe should be the same as read, except if you want to deny access to # by preventing it on subscribe.
const (
	MOSQ_ACL_NONE      = 0x00
	MOSQ_ACL_READ      = 0x01
	MOSQ_ACL_WRITE     = 0x02
	MOSQ_ACL_READWRITE = 0x03
	MOSQ_ACL_SUBSCRIBE = 0x04
	MOSQ_ACL_DENY      = 0x11
)
