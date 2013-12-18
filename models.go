package main

import (
	log "code.google.com/p/log4go"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
)

/*
This is the model for an ACL.  It stores the key of the object (the object's identifier),
the user's email, and the list of privileges.
*/
type ACL struct {
	Service    string
	Object     string
	Key        string
	User       string
	Privileges map[string]interface{}
}

// Creates an Index on the ACL collection
func (a ACL) EnsureIndex(c *mgo.Collection) error {
	index := mgo.Index{
		Key:        []string{"Service", "Object", "Key", "User"},
		Unique:     true,
		DropDups:   false,
		Background: false,
		Sparse:     false,
	}
	return c.EnsureIndex(index)
}

// Grants the given privileges on the existing ACL
func (a ACL) Grant(c *mgo.Collection, service string, object string, key string, user string,
	privileges []string) (*mgo.ChangeInfo, error) {

	selector := bson.M{"service": service, "object": object, "key": key, "user": user}
	update := copyMap(selector)

	for _, privilege := range privileges {
		update["privileges."+privilege] = "allow"
	}

	log.Finest("Granting Privilege: %s", update)
	return c.Upsert(selector, bson.M{"$set": update})
}

// Denies the privileges from the existing ACL
func (a ACL) Deny(c *mgo.Collection, service string, object string, key string, user string, privileges []string) (*mgo.ChangeInfo, error) {
	selector := bson.M{"service": service, "object": object, "key": key, "user": user}
	update := copyMap(selector)

	for _, privilege := range privileges {
		update["privileges."+privilege] = "deny"
	}

	log.Finest("Denying Privilege: %s", update)
	return c.Upsert(selector, bson.M{"$set": update})
}

// Revokes the privileges from the existing ACL
func (a ACL) Revoke(c *mgo.Collection, service string, object string, key string, user string, privileges []string) (*mgo.ChangeInfo, error) {
	selector := bson.M{"service": service, "object": object, "key": key, "user": user}
	toRevoke := map[string]interface{}{}
	for _, privilege := range privileges {
		toRevoke["privileges."+privilege] = ""
	}
	log.Finest("Revoking Privilege: %s, %s", selector, toRevoke)
	return c.Upsert(selector, bson.M{"$unset": toRevoke})
}

// Sets the privileges to a whole new ACL
func (a ACL) Set(c *mgo.Collection, service string, object string, key string, user string, privileges map[string]interface{}) (*mgo.ChangeInfo, error) {
	selector := bson.M{"service": service, "object": object, "key": key, "user": user}
	update := copyMap(selector)
	update["privileges"] = privileges

	log.Finest("Setting Privilege: %s", update)
	return c.Upsert(selector, update)
}

// Retrieves the ACL from the collection using the object's key and the user, if the user is granted privileges
func (a ACL) Has(c *mgo.Collection, service string, object string, key string, user string, privileges []string) error {
	selector := bson.M{"service": service, "object": object, "key": key, "user": user}
	for _, privilege := range privileges {
		selector["privileges."+privilege] = "allow"
	}

	log.Finest("Checking user has privilege: %s", selector)
	result := ACL{}
	return c.Find(selector).One(&result)
}

// Retrieves the ACL from the collection using the object's key and the user
func (a ACL) Get(c *mgo.Collection, service string, object string, key string, user string) (ACL, error) {
	selector := bson.M{"service": service, "object": object, "key": key, "user": user}
	result := ACL{}
	err := c.Find(selector).One(&result)
	return result, err
}

// Retrieves the ACL list from the collection
func (a ACL) List(c *mgo.Collection, service string, object string, key string, user string) ([]ACL, error) {
	result := []ACL{}

	query := bson.M{"service": service, "object": object}
	if key != "" {
		query["key"] = key
	}

	if user != "" {
		query["user"] = user
	}

	err := c.Find(query).All(&result)

	return result, err
}

// Retrieves a list of the keys for a service/object/user combo that the user has "allow" privileges for
func (a ACL) Match(c *mgo.Collection, service string, object string, user string, privileges []string) ([]string, error) {
	selector := bson.M{"service": service, "object": object, "user": user}
	for _, privilege := range privileges {
		selector["privileges."+privilege] = "allow"
	}

	log.Finest("Matching user privileges to keys: %s", selector)
	result := []string{}
	err := c.Find(selector).Distinct("key", &result)
	return result, err
}

// Retrieves the list of services from the collection
func (a ACL) ListServices(c *mgo.Collection) ([]string, error) {
	result := []string{}
	err := c.Find(bson.M{}).Distinct("service", &result)

	return result, err
}

// Retrieves the list of objects for a service from the collection
func (a ACL) ListObjects(c *mgo.Collection, service string) ([]string, error) {
	result := []string{}
	err := c.Find(bson.M{"service": service}).Distinct("object", &result)

	return result, err
}
