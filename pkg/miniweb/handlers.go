package miniweb

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/pelletier/go-toml"
	"golang.org/x/net/html"
)

type handlerFactoryFunc func(handlerConfig, domainTree) (http.Handler, error)

var handlerFactoryRegistry = map[string]handlerFactoryFunc{
	"status":    newStatusHandler,
	"file":      newFileHandler,
	"setCookie": newSetCookieHandler,
	"getCookie": newGetCookieHandler,
}

type statusHandlerOptions struct {
	Status int    // HTTP status code to return
	Text   string // MIME text/plain response body payload
}

// newStatusHandler constructs  the basic testing handler, for emitting fixed strings
func newStatusHandler(config handlerConfig, domain domainTree) (http.Handler, error) {
	optionTree, err := toml.TreeFromMap(config.Options)
	if err != nil {
		return nil, fmt.Errorf("newStatusHandler(...): %w", err)
	}

	var options statusHandlerOptions
	err = optionTree.Unmarshal(&options)
	if err != nil {
		return nil, fmt.Errorf("newStatusHandler(...): %w", err)
	}

	if options.Status == 0 {
		options.Status = http.StatusOK
	}
	if options.Text == "" {
		options.Text = http.StatusText(options.Status)
	}

	return http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		//writer.Header().Set("Content-Length", fmt.Sprintf("%d", len(options.Text)))
		//writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(options.Status)
		writer.Write([]byte(options.Text))
	}), nil
}

type fileHandlerOptions struct {
	Index string // filename to append for directory entries (e.g., index.html)
}

// newFileHandler constructs a handler for basic HTTP file serving (using domain's openFile semantics)
func newFileHandler(config handlerConfig, domain domainTree) (http.Handler, error) {
	optionTree, err := toml.TreeFromMap(config.Options)
	if err != nil {
		return nil, fmt.Errorf("newFileHandler(...): %w", err)
	}

	var options fileHandlerOptions
	err = optionTree.Unmarshal(&options)
	if err != nil {
		return nil, fmt.Errorf("newFileHandler(...): %w", err)
	}

	if options.Index == "" {
		options.Index = "index.html"
	}

	return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
		file, stat, err := domain.openFile(req.URL.Path, options.Index)
		if file != nil {
			defer (*file).Close()
		}

		if os.IsNotExist(err) {
			writer.WriteHeader(http.StatusNotFound)
		} else if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			writer.Write([]byte(err.Error()))
		} else {
			http.ServeContent(writer, req, stat.Name(), stat.ModTime(), *file)
		}
	}), nil
}

type setCookiePostPayload struct {
	Cookies  []http.Cookie
	Location string
}

// newSetCookieHandler constructs a handler for POSTs that take a JSON-specified list of cookies to set and meta-refresh-redirect to a specified URL
func newSetCookieHandler(config handlerConfig, domain domainTree) (http.Handler, error) {
	return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost || req.Header.Get("Content-Type") != "application/json" {
			writer.WriteHeader(http.StatusBadRequest)
			writer.Write([]byte("POST JSON"))
			return
		}

		decoder := json.NewDecoder(req.Body)
		var payload setCookiePostPayload
		err := decoder.Decode(&payload)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			writer.Write([]byte("POST _good_ JSON"))
			return
		}

		for _, cookie := range payload.Cookies {
			http.SetCookie(writer, &cookie)
		}

		var htmlBody string
		if payload.Location != "" {
			htmlBody = "<html><head><meta http-equiv=\"refresh\" content=\"0;url=" + html.EscapeString(payload.Location) + "\"></head><body>Please wait...</body></html>"
			writer.Header().Add("Content-Type", "text/html")
		}
		writer.Write([]byte(htmlBody))
	}), nil
}

type getCookiePostPayload struct {
	CookieName string
}

// newGetCookieHandler constructs a handler for POSTs that specify a Cookie: to return by name (or 404 if that cookie wasn't sent)
func newGetCookieHandler(config handlerConfig, domain domainTree) (http.Handler, error) {
	return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost || req.Header.Get("Content-Type") != "application/json" {
			writer.WriteHeader(http.StatusBadRequest)
			writer.Write([]byte("POST JSON"))
			return
		}

		decoder := json.NewDecoder(req.Body)
		var payload getCookiePostPayload
		err := decoder.Decode(&payload)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			writer.Write([]byte("POST _good_ JSON"))
			return
		}

		cookie, err := req.Cookie(payload.CookieName)
		if err == http.ErrNoCookie {
			writer.WriteHeader(http.StatusNotFound)
			return
		} else if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			writer.Write([]byte(err.Error()))
			return
		}

		writer.Write([]byte(cookie.Value))
	}), nil
}
