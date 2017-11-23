package backends

type JWT struct {
	Remote bool

	JWTSecret string

	Method       string
	UserUri      string
	SuperuserUri string
	AclUri       string
	Hostname     string
	Port         string
	Ip           string
	WithTLS      bool
	VerifyPeer   bool
}

var allowedOpts = map[string]bool{
	"method":        true,
	"user_uri":      true,
	"superuser_uri": true,
	"acl_uri":       true,
	"hostname":      true,
	"port":          true,
	"ip":            true,
	"with_tls":      true,
	"verify_peer":   true,
}

func NewJWT(authOpts map[string]string) (JWT, error) {

	var jwt = JWT{
		Remote:     false,
		WithTLS:    false,
		VerifyPeer: false,
	}

	if remote, ok := authOpts["remote"]; ok && authOpts["remote"] == "true" {
		jwt.Remote = true
	}

	if method, ok := authOpts["method"]; ok {
		jwt.Method = authOpts["method"]
	}

	return nil, nil
}
