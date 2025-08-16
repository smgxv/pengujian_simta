package utils

import "fmt"

// ParseInt converts a string to an integer
func ParseInt(s string) int {
	var i int
	fmt.Sscanf(s, "%d", &i)
	return i
}

// Helper function to handle null strings
func StringOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
