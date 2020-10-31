package backends

import (
	"strconv"

	"github.com/iegomez/mosquitto-go-auth/backends/js"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type jsJWTChecker struct {
	stackDepthLimit int
	msMaxDuration   int64

	userScript      string
	superuserScript string
	aclScript       string

	options tokenOptions

	runner *js.Runner
}

const (
	defaultStackDepthLimit = 32
	defaultMsMaxDuration   = 200
)

func NewJsJWTChecker(authOpts map[string]string, options tokenOptions) (jwtChecker, error) {
	checker := &jsJWTChecker{
		stackDepthLimit: defaultStackDepthLimit,
		msMaxDuration:   defaultMsMaxDuration,
		options:         options,
	}

	if stackLimit, ok := authOpts["jwt_js_stack_depth_limit"]; ok {
		limit, err := strconv.ParseInt(stackLimit, 10, 64)
		if err != nil {
			log.Errorf("invalid stack depth limit %s, defaulting to 32", stackLimit)
		} else {
			checker.stackDepthLimit = int(limit)
		}
	}

	if maxDuration, ok := authOpts["jwt_js_ms_max_duration"]; ok {
		duration, err := strconv.ParseInt(maxDuration, 10, 64)
		if err != nil {
			log.Errorf("invalid stack depth limit %s, defaulting to 32", maxDuration)
		} else {
			checker.msMaxDuration = duration
		}
	}

	if userScriptPath, ok := authOpts["jwt_js_user_script_path"]; ok {
		script, err := js.LoadScript(userScriptPath)
		if err != nil {
			return nil, err
		}

		checker.userScript = script
	} else {
		return nil, errors.New("missing jwt_js_user_script_path")
	}

	if superuserScriptPath, ok := authOpts["jwt_js_superuser_script_path"]; ok {
		script, err := js.LoadScript(superuserScriptPath)
		if err != nil {
			return nil, err
		}

		checker.superuserScript = script
	} else {
		return nil, errors.New("missing jwt_js_superuser_script_path")
	}

	if aclScriptPath, ok := authOpts["jwt_js_acl_script_path"]; ok {
		script, err := js.LoadScript(aclScriptPath)
		if err != nil {
			return nil, err
		}

		checker.aclScript = script
	} else {
		return nil, errors.New("missing jwt_js_acl_script_path")
	}

	checker.runner = js.NewRunner(checker.stackDepthLimit, checker.msMaxDuration)

	return checker, nil
}

func (o *jsJWTChecker) GetUser(token string) bool {
	params := map[string]interface{}{
		"token": token,
	}

	if o.options.parseToken {
		username, err := getUsernameForToken(o.options, token, o.options.skipUserExpiration)

		if err != nil {
			log.Printf("jwt get user error: %s", err)
			return false
		}

		params["username"] = username
	}

	granted, err := o.runner.RunScript(o.userScript, params)
	if err != nil {
		log.Errorf("js error: %s", err)
	}

	return granted
}

func (o *jsJWTChecker) GetSuperuser(token string) bool {
	params := map[string]interface{}{
		"token": token,
	}

	if o.options.parseToken {
		username, err := getUsernameForToken(o.options, token, o.options.skipUserExpiration)

		if err != nil {
			log.Printf("jwt get user error: %s", err)
			return false
		}

		params["username"] = username
	}

	granted, err := o.runner.RunScript(o.superuserScript, params)
	if err != nil {
		log.Errorf("js error: %s", err)
	}

	return granted
}

func (o *jsJWTChecker) CheckAcl(token, topic, clientid string, acc int32) bool {
	params := map[string]interface{}{
		"token":    token,
		"topic":    topic,
		"clientid": clientid,
		"acc":      acc,
	}

	if o.options.parseToken {
		username, err := getUsernameForToken(o.options, token, o.options.skipACLExpiration)

		if err != nil {
			log.Printf("jwt get user error: %s", err)
			return false
		}

		params["username"] = username
	}

	granted, err := o.runner.RunScript(o.aclScript, params)
	if err != nil {
		log.Errorf("js error: %s", err)
	}

	return granted
}

func (o *jsJWTChecker) Halt() {
	// NO-OP
}
