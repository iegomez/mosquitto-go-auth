package backends

import (
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"strconv"
	"strings"
)

type LDAP struct {
	Conn                     *ldap.Conn
	Url                      string
	BaseDN                   string
	GroupBaseDN              string
	BindDN                   string
	BindPass                 string
	UserFilter               string
	GroupFilter              string
	SuperuserFilter          string
	AclTopicPatternAttribute string
	AclAccAttribute          string
}

func NewLDAP(authOpts map[string]string, logLevel log.Level) (LDAP, error) {

	log.SetLevel(logLevel)

	ldapOk := true
	missingOptions := ""

	var o = LDAP{
		Url:                      "ldap://localhost:389",
		GroupBaseDN:              "",
		GroupFilter:              "(member=%s)",
		SuperuserFilter:          "",
		AclTopicPatternAttribute: "",
		AclAccAttribute:          "",
	}

	if host, ok := authOpts["ldap_url"]; ok {
		o.Url = host
	}

	if baseDN, ok := authOpts["ldap_base_dn"]; ok {
		o.BaseDN = baseDN
	} else {
		ldapOk = false
		missingOptions += " ldap_base_dn"
	}

	if groupBaseDN, ok := authOpts["ldap_group_base_dn"]; ok {
		o.GroupBaseDN = groupBaseDN
	}

	if bindDN, ok := authOpts["ldap_bind_dn"]; ok {
		o.BindDN = bindDN
	} else {
		ldapOk = false
		missingOptions += " ldap_bind_dn"
	}

	if bindPass, ok := authOpts["ldap_bind_password"]; ok {
		o.BindPass = bindPass
	} else {
		ldapOk = false
		missingOptions += " ldap_bind_password"
	}

	if userFilter, ok := authOpts["ldap_user_filter"]; ok {
		o.UserFilter = userFilter
	} else {
		ldapOk = false
		missingOptions += " ldap_user_filter"
	}

	if groupFilter, ok := authOpts["ldap_group_filter"]; ok {
		o.GroupFilter = groupFilter
	}

	if superuserFilter, ok := authOpts["ldap_superuser_filter"]; ok {
		o.SuperuserFilter = superuserFilter
	}

	if aclTopicPatternAttribute, ok := authOpts["ldap_acl_topic_pattern_attribute"]; ok {
		o.AclTopicPatternAttribute = aclTopicPatternAttribute
	}

	if aclAccAttribute, ok := authOpts["ldap_acl_acc_attribute"]; ok {
		o.AclAccAttribute = aclAccAttribute
	}

	//Exit if any mandatory option is missing.
	if !ldapOk {
		return o, errors.Errorf("LDAP backend error: missing options:%s", missingOptions)
	}

	//Check if the LDAP server is reachable
	conn, err := ldap.DialURL(o.Url)
	if err != nil {
		log.Debugf("LDAP connection error: %s", err)
		return o, err
	}
	o.Conn = conn

	err = conn.Bind(o.BindDN, o.BindPass)
	if err != nil {
		log.Debugf("LDAP bind error: %s", err)
		return o, err
	}

	return o, nil
}

func (o LDAP) GetUser(username, password, clientid string) (bool, error) {

	searchRequest := ldap.NewSearchRequest(
		o.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf(o.UserFilter, ldap.EscapeFilter(username)),
		[]string{"dn"},
		nil,
	)

	searchResult, err := o.Conn.Search(searchRequest)
	if err != nil {
		log.Debugf("LDAP user search error: %s", err)
		return false, err
	}
	if len(searchResult.Entries) != 1 {
		log.Debugf("LDAP user search returned %d entries", len(searchResult.Entries))
		return false, nil
	}

	userDN := searchResult.Entries[0].DN

	userConn, err := ldap.DialURL(o.Url)
	if err != nil {
		log.Debugf("LDAP user connection error: %s", err)
		return false, err
	}
	defer func(userConn *ldap.Conn) {
		err := userConn.Close()
		if err != nil {
			log.Errorf("LDAP user cleanup error: %s", err)
		}
	}(userConn)

	err = userConn.Bind(userDN, password)
	if err != nil {
		log.Debugf("LDAP user bind error: %s", err)
		return false, err
	}

	return true, nil
}

func (o LDAP) GetSuperuser(username string) (bool, error) {

	//If there's no superuser filter, assume all privileges for all users.
	if o.SuperuserFilter == "" {
		return false, nil
	}

	searchRequest := ldap.NewSearchRequest(
		o.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf(o.SuperuserFilter, ldap.EscapeFilter(username)),
		[]string{"dn"},
		nil,
	)

	searchResult, err := o.Conn.Search(searchRequest)
	if err != nil {
		log.Debugf("LDAP superuser search error: %s", err)
		return false, nil
	}
	if len(searchResult.Entries) != 1 {
		log.Debugf("LDAP superuser search returned %d entries", len(searchResult.Entries))
		return false, err
	}

	return true, nil
}

// checks whether an MQTT topic matches a pattern with wildcards (+, #) according to MQTT spec rules.
func matchMQTT(topic, pattern string) bool {
	topicLevels := strings.Split(topic, "/")
	patternLevels := strings.Split(pattern, "/")

	for i := 0; i < len(patternLevels); i++ {
		// If we've run out of topic levels but pattern still has more
		if i >= len(topicLevels) {
			// Only valid if current pattern is '#' AND it's the last part
			// '#' can match zero or more topic levels, so it can match "nothing"
			return patternLevels[i] == "#" && i == len(patternLevels)-1
		}

		switch patternLevels[i] {
		case "#":
			// '#' must be last in pattern; if so, it matches all remaining topic levels
			return i == len(patternLevels)-1

		case "+":
			// '+' matches exactly one topic level, so we just continue to next
			continue

		default:
			// If it's not a wildcard, it must match the topic level exactly
			if patternLevels[i] != topicLevels[i] {
				return false
			}
		}
	}

	// After processing pattern, topic must not have any extra levels
	return len(topicLevels) == len(patternLevels)
}

func (o LDAP) CheckAcl(username, topic, clientid string, acc int32) (bool, error) {

	attributes := []string{}

	if o.AclTopicPatternAttribute != "" {
		attributes = append(attributes, o.AclTopicPatternAttribute)
	}

	if o.AclAccAttribute != "" {
		attributes = append(attributes, o.AclAccAttribute)
	}

	//If there are no acl attributes defined, assume all privileges for all users.
	if len(attributes) == 0 {
		return true, nil
	}

	//If there is no groupBaseDN, return false.
	if o.GroupBaseDN == "" {
		log.Debugf("ldap_group_base_dn not set, cannot check ACL")
		return false, nil
	}

	searchRequest := ldap.NewSearchRequest(
		o.GroupBaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf(o.GroupFilter, ldap.EscapeFilter(username)),
		attributes,
		nil,
	)

	searchResult, err := o.Conn.Search(searchRequest)
	if err != nil {
		log.Debugf("LDAP acl search error: %s", err)
		return false, err
	}
	if len(searchResult.Entries) == 0 {
		log.Debugf("LDAP acl search returned 0 entries", len(searchResult.Entries))
	}

	// Iterate through the results and check for topic access
	for _, entry := range searchResult.Entries {
		// If there is an acc attribute, check if the access level matches.
		if o.AclAccAttribute != "" {
			accessStr := entry.GetAttributeValue(o.AclAccAttribute)
			if accessStr != "" {
				access, err := strconv.ParseInt(accessStr, 10, 32)
				if err != nil {
					log.Debugf("LDAP acl failed to parse %s as int32: %s", accessStr, err)
					continue
				}

				// Check if all bits in acc are present in access
				if int32(access)&acc != acc {
					continue
				}
			}
		}

		var topicPatterns []string

		if o.AclTopicPatternAttribute != "" {
			topicPatterns = entry.GetAttributeValues(o.AclTopicPatternAttribute)
		}

		// Check the access levels and topic patterns for a match
		for _, pattern := range topicPatterns {
			if matchMQTT(topic, pattern) {
				return true, nil
			}
		}
	}

	// No matching topic pattern found
	return false, nil
}

// GetName returns the backend's name
func (b LDAP) GetName() string {
	return "LDAP"
}

// Halt closes the ldap connection.
func (o LDAP) Halt() {
	if o.Conn != nil {
		err := o.Conn.Close()
		if err != nil {
			log.Errorf("LDAP cleanup error: %s", err)
		}
	}
}
