package rebbleHandlers

import (
	"github.com/gorilla/mux"
)

// Handlers returns a mux.Router with all possible routes already setup.
func Handlers(context *HandlerContext) *mux.Router {
	r := mux.NewRouter()
	r.Handle("/", routeHandler{context, HomeHandler}).Methods("GET")
	r.Handle("/client_ids", routeHandler{context, ClientIdsHandler}).Methods("GET")
	r.Handle("/user/login", routeHandler{context, AccountLoginHandler}).Methods("POST")
	r.Handle("/user/info", routeHandler{context, AccountInfoHandler}).Methods("POST")
	r.Handle("/user/update/name", routeHandler{context, AccountUpdateNameHandler}).Methods("POST")
	r.Handle("/user/name/{id}", routeHandler{context, AccountGetNameHandler}).Methods("GET")
	r.Handle("/admin/rebuild/db", routeHandler{context, AdminRebuildDBHandler}).Host("localhost")
	r.Handle("/admin/version", routeHandler{context, AdminVersionHandler})

	return r
}
