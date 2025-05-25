package topics

import (
	"fmt"
	. "github.com/smartystreets/goconvey/convey"
	"testing"
)

func TestTopicsMatch(t *testing.T) {
	Convey("Match should match mqtt topics correctly", t, func() {
		tests := []struct {
			pattern  string
			topic    string
			expected bool
		}{
			// Exact matches
			{"a/b/c", "a/b/c", true},
			{"a/b", "a/b", true},
			{"a", "a", true},

			{"a/b", "a/x", false},
			{"a/b", "x/b", false},

			// Single-level wildcard +
			{"a/+/c", "a/b/c", true},
			{"a/+/c", "a/x/c", true},
			{"+/+/+", "a/b/c", true},
			{"+/b/+", "a/b/c", true},
			{"a/b/+", "a/b/c", true},
			{"+", "a", true},

			{"a/+/c", "a/x/x", false},

			// Wrong segment count with +
			{"a/+/c", "a/c", false},
			{"a/+/c", "a/b/c/d", false},
			{"+/+", "a", false},
			{"+/+", "a/b/c", false},

			// Multi-level wildcard #
			{"a/b/#", "a/b", true},
			{"a/b/#", "a/b/c", true},
			{"a/b/#", "a/b/c/d/e", true},
			{"#", "a", true},
			{"#", "a/b/c", true},
			{"#", "/", true},
			{"#", "//", true},

			{"a/b/#", "a", false},
			{"a/b/#", "a/x/c", false},

			// # cannot match middle segments
			{"a/#/c", "a/b/c", false},

			// Pattern longer than topic
			{"a/b/c/d", "a/b/c", false},
			{"a/b/+", "a/b", false},

			// Topic longer than pattern
			{"a/b", "a/b/c", false},
			{"a/b/c", "a/b/c/d", false},
			{"a/b/+", "a/b/c/d", false},

			// Empty topic and pattern
			{"", "", true},
			{"#", "", true},
			{"+", "", true},

			{"", "a", false},

			// Trailing slashes
			{"a/b/", "a/b/", true},

			{"a/b", "a/b/", false},
			{"a/b/", "a/b", false},

			// Topic with empty segments
			{"a//c", "a//c", true},
			{"a/+/c", "a//c", true},
		}

		for i, test := range tests {
			Convey(fmt.Sprintf("#%d: Match(%s, %s)", i, test.pattern, test.topic), func() {
				result := Match(test.pattern, test.topic)

				if result != test.expected {
					fmt.Printf("\nFAILED test #%d: pattern=%q topic=%q → got=%v, expected=%v\n", i, test.topic, test.pattern, result, test.expected)
				}

				So(result, ShouldEqual, test.expected)
			})
		}
	})
}
