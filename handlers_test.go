package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"labix.org/v2/mgo"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthorizer(t *testing.T) {

	fmt.Println("Initializing Tests")

	Initialize()

	Application.Debug = true
	Application.UnitTest = true

	session, db, c, err := getMongo()
	if err != nil {
		t.Fatal(err)
	} else {
		fmt.Println("Dropping test DB @ start")
		db.DropDatabase()
	}

	defer releaseMongo(session, db)

	ts := Application.StartUnitTest()
	defer ts.Close()

	testGrant(t, ts, c)

	testDeny(t, ts, c)

	testGrantOverwrite(t, ts, c)

	testRevoke(t, ts, c)

	testSet(t, ts, c)

	testSetNew(t, ts, c)

	testHas(t, ts, c)

	testGet(t, ts, c)

	testMatch(t, ts, c)

	testList(t, ts, c)
	testListUser(t, ts, c)
	testListKey(t, ts, c)

	testListServices(t, ts, c)

	testListObjects(t, ts, c)
}

func testListServices(t *testing.T, ts *httptest.Server, c *mgo.Collection) {
	url := fmt.Sprintf("%s/v1/service/", ts.URL)
	fmt.Println("List services at URL: ", url)
	res, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 {
		t.Fatal("Unexpected status code from list services call. Got Status: ", res.Status)
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatal("Error getting response body: ", err)
	}

	fmt.Println("Output from list services call: ", string(body))

	output := []string{}
	err = json.Unmarshal(body, &output)
	if err != nil {
		t.Fatal("Error parsing response body: ", err)
	}

	if len(output) != 1 {
		t.Fatal("Incorrect number of output from list services call")
	}
}

func testListObjects(t *testing.T, ts *httptest.Server, c *mgo.Collection) {
	url := fmt.Sprintf("%s/v1/service/%s/object/", ts.URL, "service1")
	fmt.Println("List service objects at URL: ", url)
	res, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 {
		t.Fatal("Unexpected status code from list service objects call. Got Status: ", res.Status)
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatal("Error getting response body: ", err)
	}

	fmt.Println("Output from list service objects call: ", string(body))

	output := []string{}
	err = json.Unmarshal(body, &output)
	if err != nil {
		t.Fatal("Error parsing response body: ", err)
	}

	if len(output) != 1 {
		t.Fatal("Incorrect number of output from list service objects call")
	}
}

func testListKey(t *testing.T, ts *httptest.Server, c *mgo.Collection) {
	url := fmt.Sprintf("%s/v1/service/%s/object/%s/list/?key=1", ts.URL, "service1", "object1")
	fmt.Println("List privileges at URL: ", url)
	res, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 {
		t.Fatal("Unexpected status code from get call. Got Status: ", res.Status)
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatal("Error getting response body: ", err)
	}

	fmt.Println("Output from list call: ", string(body))

	output := []map[string]interface{}{}
	err = json.Unmarshal(body, &output)
	if err != nil {
		t.Fatal("Error parsing response body: ", err)
	}

	if len(output) != 1 {
		t.Fatal("Incorrect number of output from list privilege call")
	}
}

func testListUser(t *testing.T, ts *httptest.Server, c *mgo.Collection) {
	url := fmt.Sprintf("%s/v1/service/%s/object/%s/list/?user=john", ts.URL, "service1", "object1")
	fmt.Println("List privileges at URL: ", url)
	res, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 {
		t.Fatal("Unexpected status code from get call. Got Status: ", res.Status)
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatal("Error getting response body: ", err)
	}

	fmt.Println("Output from list call: ", string(body))

	output := []map[string]interface{}{}
	err = json.Unmarshal(body, &output)
	if err != nil {
		t.Fatal("Error parsing response body: ", err)
	}

	if len(output) != 2 {
		t.Fatal("Incorrect number of output from list privilege call")
	}
}

func testList(t *testing.T, ts *httptest.Server, c *mgo.Collection) {
	url := fmt.Sprintf("%s/v1/service/%s/object/%s/list/?user=john&key=1", ts.URL, "service1", "object1")
	fmt.Println("List privileges at URL: ", url)
	res, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 {
		t.Fatal("Unexpected status code from get call. Got Status: ", res.Status)
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatal("Error getting response body: ", err)
	}

	fmt.Println("Output from list call: ", string(body))

	output := []map[string]interface{}{}
	err = json.Unmarshal(body, &output)
	if err != nil {
		t.Fatal("Error parsing response body: ", err)
	}

	if len(output) != 1 {
		t.Fatal("Incorrect number of output from list privilege call")
	}
}

func testMatch(t *testing.T, ts *httptest.Server, c *mgo.Collection) {
	url := fmt.Sprintf("%s/v1/service/%s/object/%s/match/", ts.URL, "service1", "object1")
	dataMap := []map[string]interface{}{
		map[string]interface{}{
			"user":       "john",
			"privileges": []string{"far", "fal"},
		},
	}
	dataStr, err := json.Marshal(dataMap)
	data := bytes.NewReader(dataStr)

	client := &http.Client{}
	req, err := http.NewRequest("GET", url, data)
	fmt.Println("Match privileges at URL: ", url)
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 {
		t.Fatal("Unexpected status code from match call. Got Status: ", res.Status)
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatal("Error getting response body: ", err)
	}

	fmt.Println("Output from match call: ", string(body))

	output := []map[string]interface{}{}
	err = json.Unmarshal(body, &output)
	if err != nil {
		t.Fatal("Error parsing response body: ", err)
	}

	if len(output) != 1 {
		t.Fatal("Incorrect number of output from match privilege call")
	}
}

func testGet(t *testing.T, ts *httptest.Server, c *mgo.Collection) {
	url := fmt.Sprintf("%s/v1/service/%s/object/%s/get/", ts.URL, "service1", "object1")
	dataMap := []map[string]interface{}{
		map[string]interface{}{
			"user": "john",
			"key":  "1",
		},
		map[string]interface{}{
			"user": "john",
			"key":  "2",
		},
	}
	dataStr, err := json.Marshal(dataMap)
	data := bytes.NewReader(dataStr)

	client := &http.Client{}
	req, err := http.NewRequest("GET", url, data)
	fmt.Println("Get privileges at URL: ", url)
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 {
		t.Fatal("Unexpected status code from get call. Got Status: ", res.Status)
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatal("Error getting response body: ", err)
	}

	fmt.Println("Output from get call: ", string(body))

	output := []map[string]interface{}{}
	err = json.Unmarshal(body, &output)
	if err != nil {
		t.Fatal("Error parsing response body: ", err)
	}

	if len(output) != 2 {
		t.Fatal("Incorrect number of output from get privilege call")
	}
}

func testHas(t *testing.T, ts *httptest.Server, c *mgo.Collection) {
	url := fmt.Sprintf("%s/v1/service/%s/object/%s/has/", ts.URL, "service1", "object1")
	dataMap := []map[string]interface{}{
		map[string]interface{}{
			"user":       "john",
			"key":        "1",
			"privileges": []string{"far", "fal"},
		},
		map[string]interface{}{
			"user":       "john",
			"key":        "1",
			"privileges": []string{"far", "faz"},
		},
	}
	dataStr, err := json.Marshal(dataMap)
	data := bytes.NewReader(dataStr)

	client := &http.Client{}
	req, err := http.NewRequest("GET", url, data)
	fmt.Println("Has privileges at URL: ", url)
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 {
		t.Fatal("Unexpected status code from has call. Got Status: ", res.Status)
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatal("Error getting response body: ", err)
	}

	fmt.Println("Output from Has call: ", string(body))

	output := []map[string]interface{}{}
	err = json.Unmarshal(body, &output)
	if err != nil {
		t.Fatal("Error parsing response body: ", err)
	}

	if len(output) != 2 {
		t.Fatal("Incorrect number of output from has privilege call")
	}

	if output[0]["privilege"] != "allow" {
		t.Fatal("Should not have denied first has privilege")
	}
	if output[1]["privilege"] != "deny" {
		t.Fatal("Should not have allowed second has privilege")
	}
}

func testSetNew(t *testing.T, ts *httptest.Server, c *mgo.Collection) {
	url := fmt.Sprintf("%s/v1/service/%s/object/%s/set/", ts.URL, "service1", "object1")
	dataMap := []map[string]interface{}{
		map[string]interface{}{
			"user":       "john",
			"key":        "2",
			"privileges": map[string]interface{}{"far": "allow", "faz": "deny"},
		},
	}
	dataStr, err := json.Marshal(dataMap)
	data := bytes.NewReader(dataStr)

	client := &http.Client{}
	req, err := http.NewRequest("PUT", url, data)
	fmt.Println("Set privileges at URL: ", url)
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 204 {
		t.Fatal("Unexpected status code from deny call. Got Status: ", res.Status)
	}

	acl, err := ACL{}.Get(c, "service1", "object1", "2", "john")
	if err != nil {
		t.Fatal("Error getting document", err)
	}

	fmt.Println("Output From Set: ", acl)
	if len(acl.Privileges) != 2 {
		t.Fatal("Incorrect number of privileges: ", len(acl.Privileges))
	} else if acl.Privileges["far"] != "allow" && acl.Privileges["faz"] != "deny" {
		t.Fatal("Privilege not properly set")
	}
}

func testSet(t *testing.T, ts *httptest.Server, c *mgo.Collection) {
	url := fmt.Sprintf("%s/v1/service/%s/object/%s/set/", ts.URL, "service1", "object1")
	dataMap := []map[string]interface{}{
		map[string]interface{}{
			"user":       "john",
			"key":        "1",
			"privileges": map[string]interface{}{"far": "allow", "fal": "allow", "faz": "deny"},
		},
	}
	dataStr, err := json.Marshal(dataMap)
	data := bytes.NewReader(dataStr)

	client := &http.Client{}
	req, err := http.NewRequest("PUT", url, data)
	fmt.Println("Set privileges at URL: ", url)
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 204 {
		t.Fatal("Unexpected status code from deny call. Got Status: ", res.Status)
	}

	acl, err := ACL{}.Get(c, "service1", "object1", "1", "john")
	if err != nil {
		t.Fatal("Error getting document", err)
	}

	fmt.Println("Output From Set: ", acl)
	if len(acl.Privileges) != 3 {
		t.Fatal("Incorrect number of privileges: ", len(acl.Privileges))
	} else if acl.Privileges["far"] != "allow" && acl.Privileges["faz"] != "deny" {
		t.Fatal("Privilege not properly set")
	}
}

func testRevoke(t *testing.T, ts *httptest.Server, c *mgo.Collection) {
	url := fmt.Sprintf("%s/v1/service/%s/object/%s/revoke/", ts.URL, "service1", "object1")
	dataMap := []map[string]interface{}{
		map[string]interface{}{
			"user":       "john",
			"key":        "1",
			"privileges": []string{"far", "faz"},
		},
	}
	dataStr, err := json.Marshal(dataMap)
	data := bytes.NewReader(dataStr)

	fmt.Println("Revoke privileges at URL: ", url)
	res, err := http.Post(url, "application/json", data)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 204 {
		t.Fatal("Unexpected status code from revoke call. Got Status: ", res.Status)
	}

	acl, err := ACL{}.Get(c, "service1", "object1", "1", "john")
	if err != nil {
		t.Fatal("Error getting document", err)
	}

	fmt.Println("Output From Revoke: ", acl)
	if len(acl.Privileges) != 3 {
		t.Fatal("Incorrect number of privileges: ", len(acl.Privileges))
	}
}

func testDeny(t *testing.T, ts *httptest.Server, c *mgo.Collection) {
	url := fmt.Sprintf("%s/v1/service/%s/object/%s/deny/", ts.URL, "service1", "object1")
	dataMap := []map[string]interface{}{
		map[string]interface{}{
			"user":       "john",
			"key":        "1",
			"privileges": []string{"far"},
		},
	}
	dataStr, err := json.Marshal(dataMap)
	data := bytes.NewReader(dataStr)

	fmt.Println("Deny privileges at URL: ", url)
	res, err := http.Post(url, "application/json", data)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 204 {
		t.Fatal("Unexpected status code from deny call. Got Status: ", res.Status)
	}

	acl, err := ACL{}.Get(c, "service1", "object1", "1", "john")
	if err != nil {
		t.Fatal("Error getting document", err)
	}

	fmt.Println("Output From Deny: ", acl)
	if len(acl.Privileges) != 4 {
		t.Fatal("Incorrect number of privileges: ", len(acl.Privileges))
	} else if acl.Privileges["far"] != "deny" {
		t.Fatal("Privilege not properly denied")
	}
}

func testGrant(t *testing.T, ts *httptest.Server, c *mgo.Collection) {
	grantUrl := fmt.Sprintf("%s/v1/service/%s/object/%s/grant/", ts.URL, "service1", "object1")
	grantDataMap := []map[string]interface{}{
		map[string]interface{}{
			"user":       "john",
			"key":        "1",
			"privileges": []string{"faz", "boo", "baz"},
		},
	}
	grantDataStr, _ := json.Marshal(grantDataMap)
	grantData := bytes.NewReader(grantDataStr)

	fmt.Println("Granting privilege at URL: ", grantUrl)
	res, err := http.Post(grantUrl, "application/json", grantData)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 204 {
		t.Fatal("Unexpected status code from grant call. Got Status: ", res.Status)
	}

	acl, err := ACL{}.Get(c, "service1", "object1", "1", "john")
	if err != nil {
		t.Fatal("Error getting document", err)
	}

	fmt.Println("Output From Grant: ", acl)
	if len(acl.Privileges) != 3 {
		t.Fatal("Incorrect number of privileges")
	} else if acl.Privileges["faz"] != "allow" {
		t.Fatal("Privilege not properly granted")
	}

}

func testGrantOverwrite(t *testing.T, ts *httptest.Server, c *mgo.Collection) {
	grantUrl := fmt.Sprintf("%s/v1/service/%s/object/%s/grant/", ts.URL, "service1", "object1")
	grantDataMap := []map[string]interface{}{
		map[string]interface{}{
			"user":       "john",
			"key":        "1",
			"privileges": []string{"far", "foos"},
		},
	}
	grantDataStr, _ := json.Marshal(grantDataMap)
	grantData := bytes.NewReader(grantDataStr)

	fmt.Println("Granting privilege at URL: ", grantUrl)
	res, err := http.Post(grantUrl, "application/json", grantData)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 204 {
		t.Fatal("Unexpected status code from grant call. Got Status: ", res.Status)
	}

	acl, err := ACL{}.Get(c, "service1", "object1", "1", "john")
	if err != nil {
		t.Fatal("Error getting document", err)
	}

	fmt.Println("Output From Grant: ", acl)
	if len(acl.Privileges) != 5 {
		t.Fatal("Incorrect number of privileges")
	} else if acl.Privileges["far"] != "allow" {
		t.Fatal("Privilege not properly granted")
	}

}

func releaseMongo(session *mgo.Session, db *mgo.Database) {
	mongo, _ := Application.Config["mongo"].(map[string]interface{})

	keep_db, ok := mongo["keep_test_db"].(bool)
	if !ok {
		keep_db = false
	}

	if !keep_db {
		fmt.Println("Testing finished... Dropping database")
		db.DropDatabase()
	} else {
		fmt.Println("Keep test database is true, not dropping database after unit test")
	}

	session.Close()
}
