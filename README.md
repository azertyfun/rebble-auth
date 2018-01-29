## Rebble Authentication Service
The Rebble Authentication aims to provide an authentication service to all Rebble Services.
If you want to contribute join us on the [Pebble Dev Discord server](http://discord.gg/aRUAYFN), then head to `#web-services`.

## Requirements

`git`, `go`, `npm`, and `apib2swagger`.

## Dev Environment Setup
Pull down the project within your `$GOPATH`'s src folder ($GOPATH is an environment variable and is typically set to $HOME/go/ on \*nix). This can be done by running (for example) the following set of commands:

```shell
# export GOPATH=~/go/ # Optional if your didn't move your ~/go directory
mkdir -p $GOPATH/src/pebble-dev
git clone https://github.com/pebble-dev/rebble-auth.git $GOPATH/src/pebble-dev/rebble-auth
```

Then, you will need to generate a local (self signed) TLS certificate. The server only supports HTTPS, for obvious security reasons.
```shell
cd $GOPATH/src/pebble-dev/pebble-auth

# Generating private key
openssl genrsa -out server.key 2048
openssl ecparam -genkey -name secp384r1 -out server.key

# Generating certificate
openssl req -new -x509 -sha256 -key server.key -out server.crt -days 3650
```

When accessing the website for the first time, you will need to add a security exception (on Firefox) or to tell the browser to proceed anyways (on Chromium), as a self-signed certificate cannot be trusted by your browser.

## Build Process

### Backend
1. If you haven't already, you will need to run `go get -v .` within the project directory;
2. Run either `make` to build everything, or `go build -v .` to just build the go executable;
3. You can run the api with `./rebble-auth`, or run the tests with `./rebble-auth-tests`.

### Configuration

To prevent XSS, we set a CORS header. Set the `allowed_domains` key in `rebble-auth.json` to `['http://localhost:8080', 'http://localhost:8081']`.

To allow user to authenticate themselves, you will need to get OAuth2 keys for your OpenID providers. Then, fill the `client_id` and `client_secret` fields in the `rebble-auth.json` file.

## Contributing

### How Do I Help?

Everyone is welcome to help. Efforts are coordinated in the [issues tab](https://github.com/pebble-dev/rebble-auth/issues), and in the [Discord Server](http://discord.gg/aRUAYFN) in the channel `#web-services`.

If this is your first time contributing to an Open-Source project, you can [read this article](https://code.tutsplus.com/tutorials/how-to-collaborate-on-github--net-34267) to familiarize yourself with the process.

Please [format your code with go fmt](https://blog.golang.org/go-fmt-your-code) and run `go test` before committing your changes. Some editor plugins (such as vim-go) should be able to do this automatically before save.

You should start by checking the `docs/` folder!

### Code Structure

* The core of the backend is an HTTP server powered by [Go's http library](https://golang.org/pkg/net/http/) as well as [the gorilla/mux URL router and dispatcher](https://github.com/gorilla/mux);
* URLs are routed in `rebbleHandlers/routes.go` (each URL gets its custom handler across multiple files);
* When a valid URL is accessed, the corresponding handler is called. For example, `{server}/admin/version` is served by `AdminVersionHandler` in `rebbleHandlers/admin.go`;
* `rebbleHandlers/admin.go` serves the database builder (used the first time you run the backend, or every time you add new columns to the DB)
