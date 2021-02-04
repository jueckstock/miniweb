package miniweb

import (
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"log"
	"net/http"
	"os"

	"github.com/hashicorp/go-uuid"
	"github.com/pelletier/go-toml"
	"golang.org/x/net/html"
)

type handlerFactoryFunc func(handlerConfig, domainTree) (http.Handler, error)

var handlerFactoryRegistry = map[string]handlerFactoryFunc{
	"status":     newStatusHandler,
	"file":       newFileHandler,
	"setCookie":  newSetCookieHandler,
	"getCookie":  newGetCookieHandler,
	"toyTracker": newToyTrackerHandler,
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

// newToyTrackerHandler constructs a handler for GETs that shows an image indicating tracked/untracked
func newToyTrackerHandler(config handlerConfig, domain domainTree) (http.Handler, error) {
	return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		var identifier string
		var shade color.Color
		cookie, err := req.Cookie("toyTrackerID")
		if err == http.ErrNoCookie {
			identifier, err = uuid.GenerateUUID()
			shade = color.RGBA{R: 255, G: 0, B: 0, A: 255}
		} else if err == nil {
			identifier = cookie.Value
			shade = color.RGBA{R: 0, G: 255, B: 0, A: 255}
		}
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			writer.Write([]byte(err.Error()))
			return
		}

		display := image.NewRGBA(image.Rect(0, 0, 64, 64))
		draw.Draw(display, display.Bounds(), image.NewUniform(shade), image.Pt(0, 0), draw.Over)

		http.SetCookie(writer, &http.Cookie{
			Name:     "toyTrackerID",
			Value:    identifier,
			HttpOnly: false,
			Secure:   true,
			SameSite: http.SameSiteNoneMode,
			MaxAge:   24 * 3600 * 365,
		})

		writer.Header().Set("Content-Type", "image/png")
		err = png.Encode(writer, display)
		if err != nil {
			log.Printf("toyTracker: error encoding display image: %v\n", err)
		}
	}), nil
}
