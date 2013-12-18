package main

import (
	log "code.google.com/p/log4go"
	"github.com/gorilla/context"
	"github.com/johnnadratowski/droplet"
	"labix.org/v2/mgo"
	"net/http"
	_ "net/http/pprof"
)

// This is the droplet application object
var Application *droplet.Application = &droplet.Application{}

func main() {
	Initialize()

	Application.Start()

	log.Info("Server Terminated")
}

func Initialize() error {
	log.Debug("Initializing Authorizer Application")

	err := Application.Initialize()
	if err != nil {
		log.Error("An error occurred initializing droplet application: %s", err)
		panic(err)
	}

	log.Info("Starting Authorizer")

	log.Debug("Configuring MongoDB")

	mongo, ok := Application.Config["mongo"].(map[string]interface{})
	if !ok {
		log.Info("No mongo connection information available, defaulting to " +
			"dial string: 'localhost', db name: 'authorizer', collection name: 'acls'")
		Application.Config["mongo"] = map[string]interface{}{
			"dial":       "localhost",
			"db":         "authorizer",
			"collection": "acls",
		}
	} else {
		if dial, ok := mongo["dial"]; !ok {
			log.Info("Mongo dial string not specified. Using 'localhost'")
			mongo["dial"] = "localhost"
		} else {
			log.Info("Using Mongo dial string '%s' from config", dial)
		}

		if db, ok := mongo["db"]; !ok {
			log.Info("Mongo db name not specified. Using 'authorizer'")
			mongo["db"] = "authorizer"
		} else {
			log.Info("Using Mongo db name '%s' from config", db)
		}

		if collection, ok := mongo["collection"]; !ok {
			log.Info("Mongo collection name not specified. Using 'acls'")
			mongo["collection"] = "acls"
		} else {
			log.Info("Using Mongo collection name '%s' from config", collection)
		}

		Application.Config["mongo"] = mongo
	}

	Application.Handler = Handler

	ConfigureRouter()

	return nil
}

// Used to add routes to the router
func ConfigureRouter() error {
	log.Info("Configuring Routes")

	server, ok := Application.Config["server"].(map[string]interface{})
	if ok {
		https, ok := server["https"].(bool)
		if ok && https {
			Application.Router = Application.Router.Schemes("https").Subrouter()
		}
	}

	v1 := Application.Router.PathPrefix("/v1").Subrouter()
	v1_srv := v1.PathPrefix("/service").Subrouter()
	v1_serv := v1_srv.PathPrefix("/{service}").Subrouter()
	v1_obj := v1_serv.PathPrefix("/object").Subrouter()
	v1_object := v1_obj.PathPrefix("/{object}").Subrouter()

	v1_srv.HandleFunc("/", getServicesHandler).Methods("GET").Name("ListServices")

	v1_obj.HandleFunc("/", getObjectsHandler).Methods("GET").Name("ListObjects")

	v1_object.HandleFunc("/grant/", grantPrivilegesHandler).Methods("POST").Name("GrantACL")
	v1_object.HandleFunc("/deny/", denyPrivilegesHandler).Methods("POST").Name("DenyACL")
	v1_object.HandleFunc("/revoke/", revokePrivilegesHandler).Methods("POST").Name("RevokeACL")
	v1_object.HandleFunc("/set/", setPrivilegesHandler).Methods("PUT").Name("SetACL")
	v1_object.HandleFunc("/has/", hasPrivilegesHandler).Methods("GET").Name("HasACL")
	v1_object.HandleFunc("/get/", getPrivilegesHandler).Methods("GET").Name("GetACL")
	v1_object.HandleFunc("/list/", listPrivilegesHandler).Methods("GET").Name("ListACL")
	v1_object.HandleFunc("/match/", matchPrivilegesHandler).Methods("GET").Name("MatchACL")

	if Application.Debug {
		Application.Router.HandleFunc("/test/", func(w http.ResponseWriter, r *http.Request) {
			log.Info("Inside Test Function")
		})
	}

	return nil
}

// Top-level http handler.  This code will get ran on every request
func Handler(w http.ResponseWriter, r *http.Request) {

	session, db, collection, err := getMongo()
	if err != nil {
		http.Error(w, "There was an error, please try again", 500)
		return
	} else {
		defer session.Close()
	}

	context.Set(r, "mongoSession", session)
	context.Set(r, "mongoDb", db)
	context.Set(r, "mongoColl", collection)

	Application.Router.ServeHTTP(w, r)
}

func getMongo() (*mgo.Session, *mgo.Database, *mgo.Collection, error) {

	log.Debug("Getting Mongo Connection")
	mongo, _ := Application.Config["mongo"].(map[string]interface{})

	mongoDial := mongo["dial"].(string)

	session, err := mgo.Dial(mongoDial)
	if err != nil {
		log.Error("Error connecting to database")
		return nil, nil, nil, err
	}

	var db_name string
	if Application.UnitTest {
		var ok bool
		db_name, ok = mongo["test_db"].(string)
		if !ok {
			db_name = mongo["db"].(string) + "_test"
		}
	} else {
		db_name = mongo["db"].(string)
	}
	db := session.DB(db_name)

	mongoColl := mongo["collection"].(string)
	collection := db.C(mongoColl)

	return session, db, collection, nil
}
