package main

import (
	"strings"
)

// Convert []interface to []string
func interfaceSliceToStr(toCopy []interface{}) ([]string, bool) {
	strs := make([]string, len(toCopy))
	for i, _ := range toCopy {
		str, ok := toCopy[i].(string)
		if !ok {
			return nil, false
		}
		strs[i] = str
	}
	return strs, true
}

// See if the key is in the ACL list
func itemInAclList(key string, user string, list []ACL) bool {
	for _, b := range list {
		if b.Key == key && b.User == user {
			return true
		}
	}
	return false
}

// Copy a string-interface{} map
func copyMap(toCopy map[string]interface{}) map[string]interface{} {
	copyTo := map[string]interface{}{}
	for k, v := range toCopy {
		copyTo[k] = v
	}
	return copyTo
}

// Pretty-Prints map[string]string to a pretty formatted string
func mapToString(m map[string]string) string {
	output := []string{}
	for key, val := range m {
		entry := key
		if val != "" {
			entry += "=" + val
		}
		output = append(output, entry)
	}
	return strings.Join(output, ", ")
}

// Pretty-Prints map[string][]string to a pretty formatted string
func mapListToString(m map[string][]string) string {
	output := []string{}
	for key, val := range m {
		entry := key
		if val != nil {
			entry += "=" + strings.Join(val, "|")
		}
		output = append(output, entry)
	}
	return strings.Join(output, ", ")
}
