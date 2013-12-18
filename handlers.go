package main

import (
	log "code.google.com/p/log4go"
	"encoding/json"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"io/ioutil"
	"labix.org/v2/mgo"
	"net/http"
)

// Gets the body of the request
func getBody(w http.ResponseWriter, r *http.Request) ([]map[string]interface{}, error) {

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Error("An error occurred reading request body. Message: %s", err)
		http.Error(w, "An error occurred reading request body", 500)
		return nil, err
	}

	log.Debug("Request Body: %s", bodyBytes)

	var body []map[string]interface{}
	err = json.Unmarshal(bodyBytes, &body)
	if err != nil {
		log.Debug("An error occurrect parsing request body. Message: %s", err)
		http.Error(w, "Could not parse request body.  Seems to be malformed JSON.", 500)
		return nil, err
	}

	return body, nil
}

// Gets common data from a request for certain request handlers
func getRequestData(w http.ResponseWriter, r *http.Request, processBody bool) (*mgo.Collection,
	string, string, []map[string]interface{}, error) {
	c := context.Get(r, "mongoColl").(*mgo.Collection)
	vars := mux.Vars(r)
	service := vars["service"]
	object := vars["object"]

	log.Finest("Request URL Info: service: %s object: %s", service, object)

	if processBody {
		body, err := getBody(w, r)
		return c, service, object, body, err
	} else {
		return c, service, object, nil, nil
	}
}

// Gets data from a request body for processing grant/revoke
func getItemData(w http.ResponseWriter, val interface{},
	parsePrivilege bool, parseKey bool) (map[string]interface{}, string, string, []string) {
	values, ok := val.(map[string]interface{})
	if !ok {
		log.Debug("An error occurred getting body value data")
		http.Error(w, "An error occurred getting body value data", 500)
		return nil, "", "", nil
	}

	key := ""
	if parseKey {
		key, ok = values["key"].(string)
		if !ok {
			log.Debug("Missing key from an item")
			http.Error(w, "Missing key from an item", 400)
			return nil, "", "", nil
		}
	}

	user, ok := values["user"].(string)
	if !ok {
		log.Debug("Missing user from an item")
		http.Error(w, "Missing user from an item", 400)
		return nil, "", "", nil
	}

	if !parsePrivilege {
		log.Debug("Item Info: User: %s,  Key %s", user, key)
		return values, key, user, nil
	} else {
		p, ok := values["privileges"].([]interface{})
		if !ok {
			log.Debug("Missing privileges from an item")
			http.Error(w, "Missing privileges from an item", 400)
			return nil, "", "", nil
		}

		privileges, ok := interfaceSliceToStr(p)
		if !ok {
			log.Debug("Missing privileges from an item")
			http.Error(w, "Missing privileges from an item", 400)
			return nil, "", "", nil
		}
		log.Debug("Item Info: User: %s,  Key: %s,  Privileges; %s", user, key, privileges)
		return values, key, user, privileges
	}
}

// Gets the privileges from the request body values when privilegs is a map and not a list
func getPrivilegeMap(w http.ResponseWriter, values map[string]interface{}) map[string]interface{} {
	privileges, ok := values["privileges"].(map[string]interface{})
	if !ok {
		log.Debug("Missing privileges from an item")
		http.Error(w, "Missing privileges from an item", 400)
		return nil
	}
	return privileges
}

// This is a URL handler that handles updating permissions for a user on an object
func grantPrivilegesHandler(w http.ResponseWriter, r *http.Request) {

	log.Finest("Inside grant privileges.")

	c, service, object, body, err := getRequestData(w, r, true)
	if err != nil {
		// Already responded in getBody call
		return
	}

	for _, val := range body {

		_, key, user, privileges := getItemData(w, val, true, true)
		if key == "" || user == "" {
			// Couldn't get proper data from body.  Already responded in getItemData call
			return
		}

		log.Finest("Granting privilege")

		_, err = ACL{}.Grant(c, service, object, key, user, privileges)

		if err != nil {
			log.Error("An error occurred granting ACL. Body: %s\n URL: %s\nMessage: %s",
				r.Body, r.URL.RequestURI(), err)
			http.Error(w, "An error occurred granting privileges", 500)
			return
		}
	}

	w.WriteHeader(204)
}

// This is a URL handler that handles updating permissions for a user on an object
func denyPrivilegesHandler(w http.ResponseWriter, r *http.Request) {

	log.Finest("Inside deny privileges.")

	c, service, object, body, err := getRequestData(w, r, true)
	if err != nil {
		// Already responded in getBody call
		return
	}

	for _, val := range body {

		_, key, user, privileges := getItemData(w, val, true, true)
		if key == "" || user == "" {
			// Couldn't get proper data from body.  Already responded in getItemData call
			return
		}

		log.Finest("Denying privilege")

		_, err = ACL{}.Deny(c, service, object, key, user, privileges)

		if err != nil {
			log.Error("An error occurred denying privileges. Body: %s\n URL: %s\nMessage: %s",
				r.Body, r.URL.RequestURI(), err)
			http.Error(w, "An error occurred granting privileges", 500)
			return
		}
	}

	w.WriteHeader(204)
}

// This is a URL handler that handles granting permissions for a user on an object
func setPrivilegesHandler(w http.ResponseWriter, r *http.Request) {

	c, service, object, body, err := getRequestData(w, r, true)
	if err != nil {
		// Already responded in getBody call
		return
	}

	for _, val := range body {

		values, key, user, _ := getItemData(w, val, false, true)
		if key == "" || user == "" {
			// Couldn't get proper data from body.  Already responded in getItemData call
			return
		}
		privileges := getPrivilegeMap(w, values)
		if privileges == nil {
			// Already handled error in getPrivilegeMap
			return
		}

		_, err = ACL{}.Set(c, service, object, key, user, privileges)
		if err != nil {
			log.Error("An error occurred bulk creating/updating ACL in grant. "+
				"Body: %s\n URL: %s\nMessage: %s",
				r.Body, r.URL.RequestURI(), err)
			http.Error(w, "An error occurred granting privileges", 500)
			return
		}
	}

	w.WriteHeader(204)
}

// This is a URL handler that handles revoking permissions for a user on an object
func revokePrivilegesHandler(w http.ResponseWriter, r *http.Request) {
	c, service, object, body, err := getRequestData(w, r, true)
	if err != nil {
		// Already responded in getBody call
		return
	}

	for _, val := range body {

		_, key, user, privileges := getItemData(w, val, true, true)
		if key == "" || user == "" {
			// Couldn't get proper data from body.  Already responded in getItemData call
			return
		}

		_, err = ACL{}.Revoke(c, service, object, key, user, privileges)
		if err != nil {
			log.Error("An error occurred bulk creating/updating ACL in revoke. "+
				"Body: %s\n URL: %s\nMessage: %s",
				r.Body, r.URL.RequestURI(), err)
			http.Error(w, "An error occurred revoking privileges", 500)
			return
		}
	}

	w.WriteHeader(204)
}

// This is a URL handler that handles checking multiple privileges for a user on an object
func hasPrivilegesHandler(w http.ResponseWriter, r *http.Request) {
	c, service, object, body, err := getRequestData(w, r, true)
	if err != nil {
		// Already responded in getBody call
		return
	}

	output := make([]map[string]interface{}, len(body))
	for idx, val := range body {

		_, key, user, privileges := getItemData(w, val, true, true)
		if key == "" || user == "" {
			// Couldn't get proper data from body.  Already responded in getItemData call
			return
		}

		err := ACL{}.Has(c, service, object, key, user, privileges)

		var privilege string
		if err == nil {
			privilege = "allow"
		} else {
			privilege = "deny"
			if err.Error() != "not found" {
				log.Error("An error occurred in has user ACLs. "+
					"Body: %s\n URL: %s\nMessage: %s",
					r.Body, r.URL.RequestURI(), err)
				http.Error(w, "An error occurred getting privileges", 500)
				return
			}
		}

		item := map[string]interface{}{
			"key":       key,
			"user":      user,
			"privilege": privilege,
		}

		output[idx] = item
	}

	data, err := json.Marshal(output)
	if err != nil {
		log.Error(err)
		http.Error(w, "An error occurred checking privileges", 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// This is a URL handler for getting an ACL object
func getPrivilegesHandler(w http.ResponseWriter, r *http.Request) {
	c, service, object, body, err := getRequestData(w, r, true)
	if err != nil {
		// Already responded in getBody call
		return
	}

	output := make([]map[string]interface{}, len(body))
	for idx, val := range body {

		_, key, user, _ := getItemData(w, val, false, true)
		if key == "" || user == "" {
			// Couldn't get proper data from body.  Already responded in getItemData call
			return
		}

		result, err := ACL{}.Get(c, service, object, key, user)
		if err != nil && err.Error() != "not found" {
			log.Error("An error occurred getting user ACLs. "+
				"Body: %s\n URL: %s\nMessage: %s",
				r.Body, r.URL.RequestURI(), err)
			http.Error(w, "An error occurred getting privileges", 500)
			return
		}

		item := map[string]interface{}{
			"key":  key,
			"user": user,
		}

		if err == nil {
			item["privileges"] = result.Privileges
		} else {
			item["privileges"] = map[string]interface{}{}
		}

		output[idx] = item
	}

	data, err := json.Marshal(output)
	if err != nil {
		log.Error("Error marshalling get acl data: %s", err)
		http.Error(w, "An error occurred getting privileges", 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// This is a URL handler for matching objects to an allowed ACL for a user
func matchPrivilegesHandler(w http.ResponseWriter, r *http.Request) {
	c, service, object, body, err := getRequestData(w, r, true)
	if err != nil {
		// Already responded in getBody call
		return
	}

	output := make([]map[string]interface{}, len(body))
	for idx, val := range body {

		_, _, user, privileges := getItemData(w, val, true, false)
		if user == "" {
			// Couldn't get proper data from body.  Already responded in getItemData call
			return
		}

		result, err := ACL{}.Match(c, service, object, user, privileges)
		if err != nil && err.Error() != "not found" {
			log.Error("An error occurred matching user ACLs. "+
				"Body: %s\n URL: %s\nMessage: %s",
				r.Body, r.URL.RequestURI(), err)
			http.Error(w, "An error occurred matching privileges", 500)
			return
		}

		item := map[string]interface{}{
			"user": user,
		}

		if err == nil {
			item["keys"] = result
		} else {
			item["keys"] = []string{}
		}

		output[idx] = item
	}

	data, err := json.Marshal(output)
	if err != nil {
		log.Error("Error marshalling match return data: %s", err)
		http.Error(w, "An error occurred getting privileges", 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// This is a URL handler for getting ACL Lists
func listPrivilegesHandler(w http.ResponseWriter, r *http.Request) {

	c, service, object, _, _ := getRequestData(w, r, false)

	query := r.URL.Query()

	var key string
	if keyMap, ok := query["key"]; ok && len(keyMap) > 0 {
		key = keyMap[0]
	} else {
		key = ""
	}

	var user string
	if userMap, ok := query["user"]; ok && len(userMap) > 0 {
		user = userMap[0]
	} else {
		user = ""
	}

	result, err := ACL{}.List(c, service, object, key, user)
	if err != nil && err.Error() != "not found" {
		log.Error("An error occurred getting list of ACLs. "+
			"Body: %s\n URL: %s\nMessage: %s",
			r.Body, r.URL.RequestURI(), err)
		http.Error(w, "An error occurred getting privilege list", 500)
		return
	}

	data, err := json.Marshal(result)
	if err != nil {
		log.Error("Error marshalling list acl data: %s", err)
		http.Error(w, "An error occurred getting privilege list", 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// This is a URL handler for getting the services
func getServicesHandler(w http.ResponseWriter, r *http.Request) {
	c := context.Get(r, "mongoColl").(*mgo.Collection)

	result, err := ACL{}.ListServices(c)
	if err != nil {
		log.Error("An error occurred getting list of Services. "+
			"Body: %s\n URL: %s\nMessage: %s",
			r.Body, r.URL.RequestURI(), err)
		http.Error(w, "An error occurred getting services list", 500)
		return
	}

	data, err := json.Marshal(result)
	if err != nil {
		log.Error(err)
		http.Error(w, "There was an error getting services list.", 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// This is a URL handler for getting the service's objects
func getObjectsHandler(w http.ResponseWriter, r *http.Request) {
	c := context.Get(r, "mongoColl").(*mgo.Collection)
	vars := mux.Vars(r)
	service := vars["service"]

	result, err := ACL{}.ListObjects(c, service)
	if err != nil {
		log.Error("An error occurred getting list of Objects. "+
			"Body: %s\n URL: %s\nMessage: %s",
			r.Body, r.URL.RequestURI(), err)
		http.Error(w, "An error occurred getting objects list", 500)
		return
	}

	data, err := json.Marshal(result)
	if err != nil {
		log.Error(err)
		http.Error(w, "There was an error getting objects list.", 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}
