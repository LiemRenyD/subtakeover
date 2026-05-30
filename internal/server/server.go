package server

import (
	"encoding/json"
	"fmt"
	"net/http"

	"gorm.io/gorm"

	"github.com/liemreny/subtakeover/internal/storage"
	"github.com/liemreny/subtakeover/web"
)

// Server serves the dashboard and API.
type Server struct {
	db   *gorm.DB
	port int
}

// New creates a new dashboard server.
func New(db *gorm.DB, port int) *Server {
	return &Server{db: db, port: port}
}

// Start begins listening and serving HTTP requests.
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// API endpoints.
	mux.HandleFunc("/api/scans", s.handleScans)
	mux.HandleFunc("/api/findings", s.handleFindings)

	// Dashboard — serve embedded templates with SPA fallback.
	templates := web.FS()
	mux.Handle("/", spaHandler{fs: templates})

	addr := fmt.Sprintf(":%d", s.port)
	fmt.Printf("Dashboard running at http://localhost%s\n", addr)
	return http.ListenAndServe(addr, mux)
}

func (s *Server) handleScans(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var scans []storage.Scan
	s.db.Order("id DESC").Limit(20).Find(&scans)
	json.NewEncoder(w).Encode(scans)
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var findings []storage.Finding
	query := s.db.Order("id DESC").Limit(50)

	// Optional filter: ?scan_id=42
	if sid := r.URL.Query().Get("scan_id"); sid != "" {
		query = query.Where("scan_id = ?", sid).Order("id DESC").Limit(200)
	}

	query.Find(&findings)
	json.NewEncoder(w).Encode(findings)
}

// spaHandler serves files from the embedded filesystem.
// If the requested file doesn't exist, it falls back to index.html.
type spaHandler struct {
	fs http.FileSystem
}

func (h spaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path == "/" {
		path = "/index.html"
	}

	f, err := h.fs.Open(path)
	if err != nil {
		// Fallback to index.html for SPA routing.
		f, err = h.fs.Open("/index.html")
		if err != nil {
			http.Error(w, "Not Found", 404)
			return
		}
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil || stat.IsDir() {
		http.Error(w, "Not Found", 404)
		return
	}

	http.ServeContent(w, r, stat.Name(), stat.ModTime(), f)
}
