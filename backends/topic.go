package backends

import "strings"

func TopicsMatch(savedTopic, givenTopic string) bool {
	return givenTopic == savedTopic || match(strings.Split(savedTopic, "/"), strings.Split(givenTopic, "/"))
}

func match(route []string, topic []string) bool {
	switch {
	case len(route) == 0:
		return len(topic) == 0
	case len(topic) == 0:
		return route[0] == "#"
	case route[0] == "#":
		return true
	case route[0] == "+", route[0] == topic[0]:
		return match(route[1:], topic[1:])
	}

	return false
}
