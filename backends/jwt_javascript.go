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

	passClaims bool

	options tokenOptions

	runner *js.Runner
}

func NewJsJWTChecker(authOpts map[string]string, options tokenOptions) (jwtChecker, error) {
	checker := &jsJWTChecker{
		stackDepthLimit: js.DefaultStackDepthLimit,
		msMaxDuration:   js.DefaultMsMaxDuration,
		options:         options,
	}

	if stackLimit, ok := authOpts["jwt_js_stack_depth_limit"]; ok {
		limit, err := strconv.ParseInt(stackLimit, 10, 64)
		if err != nil {
			log.Errorf("invalid stack depth limit %s, defaulting to %d", stackLimit, js.DefaultStackDepthLimit)
		} else {
			checker.stackDepthLimit = int(limit)
		}
	}

	if maxDuration, ok := authOpts["jwt_js_ms_max_duration"]; ok {
		duration, err := strconv.ParseInt(maxDuration, 10, 64)
		if err != nil {
			log.Errorf("invalid stack depth limit %s, defaulting to %d", maxDuration, js.DefaultMsMaxDuration)
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

	if passClaims, ok := authOpts["jwt_js_pass_claims"]; ok && passClaims == "true" {
		checker.passClaims = true
	}

	checker.runner = js.NewRunner(checker.stackDepthLimit, checker.msMaxDuration)

	return checker, nil
}

func (o *jsJWTChecker) GetUser(token string) (bool, error) {
	params := map[string]interface{}{
		"token": token,
	}

	if o.options.parseToken {
		var err error
		if params, err = o.addDataFromJWT(params, token, o.options.skipUserExpiration); err != nil {
			return false, err
		}
	}

	granted, err := o.runner.RunScript(o.userScript, params)
	if err != nil {
		log.Errorf("js error: %s", err)
	}

	return granted, err
}

func (o *jsJWTChecker) addDataFromJWT(params map[string]interface{}, token string, skipExpiration bool) (map[string]interface{}, error) {
	claims, err := getClaimsForToken(o.options, token, skipExpiration)

	if err != nil {
		log.Printf("jwt get claims error: %s", err)
		return nil, err
	}

	if o.passClaims {
		params["claims"] = claims
	}

	if username, found := claims[o.options.userFieldKey]; found {
		params["username"] = username.(string)
	} else {
		params["username"] = ""
	}

	return params, nil
}

func (o *jsJWTChecker) GetSuperuser(token string) (bool, error) {
	params := map[string]interface{}{
		"token": token,
	}

	if o.options.parseToken {
		var err error
		if params, err = o.addDataFromJWT(params, token, o.options.skipUserExpiration); err != nil {
			return false, err
		}
	}

	granted, err := o.runner.RunScript(o.superuserScript, params)
	if err != nil {
		log.Errorf("js error: %s", err)
	}

	return granted, err
}

func (o *jsJWTChecker) CheckAcl(token, topic, clientid string, acc int32) (bool, error) {
	params := map[string]interface{}{
		"token":    token,
		"topic":    topic,
		"clientid": clientid,
		"acc":      acc,
	}

	if o.options.parseToken {
		var err error
		if params, err = o.addDataFromJWT(params, token, o.options.skipACLExpiration); err != nil {
			return false, err
		}
	}

	granted, err := o.runner.RunScript(o.aclScript, params)
	if err != nil {
		log.Errorf("js error: %s", err)
	}

	return granted, err
}

func (o *jsJWTChecker) Halt() {
	// NO-OP
}
