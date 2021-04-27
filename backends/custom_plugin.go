package backends

import (
	"fmt"
	"plugin"

	log "github.com/sirupsen/logrus"
)

type CustomPlugin struct {
	plugin       *plugin.Plugin
	init         func(map[string]string, log.Level) error
	getName      func() string
	getUser      func(username, password, clientid string) (bool, error)
	getSuperuser func(username string) (bool, error)
	checkAcl     func(username, topic, clientid string, acc int32) (bool, error)
	halt         func()
}

func NewCustomPlugin(authOpts map[string]string, logLevel log.Level) (*CustomPlugin, error) {
	plug, err := plugin.Open(authOpts["plugin_path"])
	if err != nil {
		return nil, fmt.Errorf("could not init custom plugin: %s", err)
	}

	customPlugin := &CustomPlugin{
		plugin: plug,
	}

	// Damn, this is gonna be tedious, freaking error handling!
	plInit, err := plug.Lookup("Init")

	if err != nil {
		return nil, fmt.Errorf("couldn't find func Init in plugin: %s", err)
	}

	initFunc := plInit.(func(authOpts map[string]string, logLevel log.Level) error)

	err = initFunc(authOpts, logLevel)
	if err != nil {
		return nil, fmt.Errorf("couldn't init plugin: %s", err)
	}

	customPlugin.init = initFunc

	plName, err := plug.Lookup("GetName")

	if err != nil {
		return nil, fmt.Errorf("couldn't find func GetName in plugin: %s", err)
	}

	nameFunc := plName.(func() string)
	customPlugin.getName = nameFunc

	plGetUser, err := plug.Lookup("GetUser")

	if err != nil {
		return nil, fmt.Errorf("couldn't find func GetUser in plugin: %s", err)
	}

	getUserFunc, ok := plGetUser.(func(username, password, clientid string) (bool, error))
	if !ok {
		// Here and in other places, we do this for backwards compatibility in case the custom plugin so was created before error was returned.
		tmp := plGetUser.(func(username, password, clientid string) bool)
		getUserFunc = func(username, password, clientid string) (bool, error) {
			return tmp(username, password, clientid), nil
		}
	}
	customPlugin.getUser = getUserFunc

	plGetSuperuser, err := plug.Lookup("GetSuperuser")

	if err != nil {
		return nil, fmt.Errorf("couldn't find func GetSuperuser in plugin: %s", err)
	}

	getSuperuserFunc, ok := plGetSuperuser.(func(username string) (bool, error))
	if !ok {
		tmp := plGetSuperuser.(func(username string) bool)
		getSuperuserFunc = func(username string) (bool, error) {
			return tmp(username), nil
		}
	}
	customPlugin.getSuperuser = getSuperuserFunc

	plCheckAcl, err := plug.Lookup("CheckAcl")

	if err != nil {
		return nil, fmt.Errorf("couldn't find func CheckAcl in plugin: %s", err)
	}

	checkAclFunc, ok := plCheckAcl.(func(username, topic, clientid string, acc int32) (bool, error))
	if !ok {
		tmp := plCheckAcl.(func(username, topic, clientid string, acc int32) bool)
		checkAclFunc = func(username, topic, clientid string, acc int32) (bool, error) {
			return tmp(username, topic, clientid, acc), nil
		}
	}
	customPlugin.checkAcl = checkAclFunc

	plHalt, err := plug.Lookup("Halt")

	if err != nil {
		return nil, fmt.Errorf("couldn't find func Halt in plugin: %s", err)
	}

	haltFunc := plHalt.(func())
	customPlugin.halt = haltFunc

	return customPlugin, nil
}

func (o *CustomPlugin) GetUser(username, password, clientid string) (bool, error) {
	return o.getUser(username, password, clientid)
}

func (o *CustomPlugin) GetSuperuser(username string) (bool, error) {
	return o.getSuperuser(username)
}

func (o *CustomPlugin) CheckAcl(username, topic, clientid string, acc int32) (bool, error) {
	return o.checkAcl(username, topic, clientid, acc)
}

func (o *CustomPlugin) GetName() string {
	return o.getName()
}

func (o *CustomPlugin) Halt() {
	o.halt()
}
