package rebbleHandlers

import (
	"github.com/gorilla/mux"
)

// Handlers returns a mux.Router with all possible routes already setup.
func Handlers(context *HandlerContext) *mux.Router {
	r := mux.NewRouter()
	r.Handle("/", routeHandler{context, HomeHandler}).Methods("GET")
	r.Handle("/authorize", routeHandler{context, AuthorizeHandler}).Methods("GET")
	r.Handle("/authorize_callback/{provider}", routeHandler{context, AuthorizeCallbackHandler}).Methods("GET")
	r.Handle("/user/info", routeHandler{context, AccountInfoHandler}).Methods("GET", "OPTIONS")
	r.Handle("/user/update/name", routeHandler{context, AccountUpdateNameHandler}).Methods("POST", "OPTIONS")
	r.Handle("/user/update/removeLinkedProvider", routeHandler{context, AccountRemoveLinkedProviderHandler}).Methods("POST", "OPTIONS")
	r.Handle("/user/name/{id}", routeHandler{context, AccountGetNameHandler}).Methods("GET")
	r.Handle("/admin/rebuild/db", routeHandler{context, AdminRebuildDBHandler}).Host("localhost")
	r.Handle("/admin/version", routeHandler{context, AdminVersionHandler})

	return r
}
