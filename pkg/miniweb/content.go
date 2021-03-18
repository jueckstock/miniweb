package miniweb

import (
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/armon/go-socks5"
	toml "github.com/pelletier/go-toml"
)

type handlerConfig struct {
	Name          string                 // name of handler to use (from global map of handler types)
	Options       map[string]interface{} // arbitrary options for a given handler
	httpHandler   http.Handler           // how to handle HTTP requests (if the SOCKS level sent it to our internal HTTP requests)
	socksRewriter socks5.AddressRewriter // alternate address rewriting logic (at the SOCKS level) for things like reverse proxies
}

type domainConfig struct {
	DefaultHandler handlerConfig             // default handler configuration for this namespace
	Handlers       map[string]*handlerConfig // special handler configs for specific filenames
}

type domainTree struct {
	config domainConfig    // this domain's configuration data (from TOML)
	root   http.FileSystem // the root node of the file tree backing this domain tree
}

// openFile tries to open a non-directly file given by a path under a domain tree (using the IndexFile if landing on a sub-directory)
func (t domainTree) openFile(filePath string, indexFile string) (*http.File, os.FileInfo, error) {
	if strings.HasSuffix(filePath, "/") {
		filePath = filePath + indexFile
	}

	file, err := t.root.Open(filePath)
	if err != nil {
		return nil, nil, err
	}

	stat, err := file.Stat()
	if err != nil {
		return nil, nil, err
	}

	if stat.IsDir() {
		file.Close()
		return t.openFile(path.Join(filePath, indexFile), indexFile)
	}

	return &file, stat, nil
}

// newDomainTree parses a directory's config file (if any) and constructs a domain tree
func newDomainTree(rootPath string) (*domainTree, error) {
	tree := &domainTree{
		root: http.Dir(rootPath),
	}

	file, err := tree.root.Open(".miniweb.toml")
	if os.IsNotExist(err) {
		// nothing special about this domain
	} else if err != nil {
		return nil, fmt.Errorf("newDomainTree('%s'):%w", rootPath, err)
	} else {
		tomlTree, err := toml.LoadReader(file)
		if err != nil {
			return nil, fmt.Errorf("newDomainTree('%s'):%w", rootPath, err)
		}

		err = tomlTree.Unmarshal(&tree.config)
		if err != nil {
			return nil, fmt.Errorf("newDomainTree('%s'):%w", rootPath, err)
		}
	}

	if tree.config.DefaultHandler.Name == "" {
		tree.config.DefaultHandler.Name = "file"
	}

	err = tree.resolveAllHandlers()
	if err != nil {
		return nil, fmt.Errorf("newDomainTree('%s'): %w", rootPath, err)
	}

	return tree, nil
}

func (t *domainTree) resolveAllHandlers() error {
	err := t.resolveHandler(&t.config.DefaultHandler)
	if err == nil {
		for _, hc := range t.config.Handlers {
			err = t.resolveHandler(hc)
			if err != nil {
				break
			}
		}
	}
	if err != nil {
		return fmt.Errorf("resolveAllHandlers(): %w", err)
	}
	return nil
}

// resolveHandler looks up a handler type by name and binds a ServeHTTP handler to its configuration
func (t domainTree) resolveHandler(config *handlerConfig) error {
	factoryFunc, ok := handlerFactoryRegistry[config.Name]
	if !ok {
		return fmt.Errorf("resolveHandler(...): no such handler '%s'", config.Name)
	}

	err := factoryFunc(config, t)
	if err != nil {
		return fmt.Errorf("resolveHandler(...): %w", err)
	}

	return nil
}

// httpHandler gets the HTTP httpHandler for a given path (or the default)
func (t domainTree) httpHandler(req *http.Request) http.Handler {
	reqPath := req.URL.Path
	hc, ok := t.config.Handlers[reqPath]
	if ok {
		return hc.httpHandler
	}

	return t.config.DefaultHandler.httpHandler
}

// contentTree maps DNS names to domain trees
type contentTree map[string]*domainTree

// installBuiltins adds some magic domains/handlers to the content tree
func (t contentTree) installBuiltins() error {
	domain := &domainTree{
		config: domainConfig{
			DefaultHandler: handlerConfig{
				Name: "status",
				Options: map[string]interface{}{
					"status": 404,
				},
			},
			Handlers: map[string]*handlerConfig{
				"/hello": {
					Name: "status",
					Options: map[string]interface{}{
						"status": 200,
						"text":   "hello, world!",
					},
				},
			},
		},
	}

	err := domain.resolveAllHandlers()
	if err != nil {
		return fmt.Errorf("installBuiltins(): %w", err)
	}

	t["miniweb"] = domain
	return nil
}

// newContentTree iterates over the root directory and creates a domain tree for each sub-directory (if possible)
func newContentTree(rootPath string) (contentTree, error) {
	tree := make(contentTree)
	err := tree.installBuiltins()
	if err != nil {
		return nil, fmt.Errorf("newContentTree('%s'): %w", rootPath, err)
	}

	root, err := os.Open(rootPath)
	if err != nil {
		return nil, fmt.Errorf("newContentTree('%s'): os.Open(...): %w", rootPath, err)
	}
	defer root.Close()

	items, err := root.Readdir(-1)
	if err != nil {
		return nil, fmt.Errorf("newContentTree('%s'): file.Readdir(...): %w", rootPath, err)
	}

	for _, item := range items {
		if item.IsDir() {
			domain, err := newDomainTree(filepath.Join(rootPath, item.Name()))
			if err != nil {
				return nil, fmt.Errorf("newContentTree('%s'): %w", rootPath, err)
			}
			tree[item.Name()] = domain
		}
	}

	return tree, nil
}

// domain looks up a domain tree by DNS name (nil if no such domain found)
func (t contentTree) domain(name string) *domainTree {
	return t[name]
}
