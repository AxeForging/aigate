package web

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"sort"
	"time"

	"github.com/AxeForging/aigate/domain"
	"github.com/AxeForging/aigate/services"
)

//go:embed templates/*.html.tmpl
var templatesFS embed.FS

//go:embed static
var staticFS embed.FS

type Server struct {
	addr      string
	mux       *http.ServeMux
	templates *template.Template
	configSvc *services.ConfigService
	auditSvc  *services.AuditService
}

type Options struct {
	Addr      string
	ConfigSvc *services.ConfigService
	AuditSvc  *services.AuditService
}

func New(opts Options) (*Server, error) {
	if opts.Addr == "" {
		opts.Addr = "127.0.0.1:8080"
	}
	if opts.ConfigSvc == nil {
		opts.ConfigSvc = services.NewConfigService()
	}
	if opts.AuditSvc == nil {
		opts.AuditSvc = services.NewAuditService(opts.ConfigSvc)
	}
	t, err := template.ParseFS(templatesFS, "templates/*.html.tmpl")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	s := &Server{
		addr:      opts.Addr,
		mux:       http.NewServeMux(),
		templates: t,
		configSvc: opts.ConfigSvc,
		auditSvc:  opts.AuditSvc,
	}
	s.routes()
	return s, nil
}

func (s *Server) Addr() string { return s.addr }

func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) ListenAndServe(ctx context.Context) error {
	srv := &http.Server{Addr: s.addr, Handler: s.mux}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	err := srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) routes() {
	sub, _ := fs.Sub(staticFS, "static")
	s.mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(sub))))
	s.mux.HandleFunc("/", s.handleIndex)
	s.mux.HandleFunc("/api/overview", s.handleOverview)
}

type overview struct {
	Initialized bool                  `json:"initialized"`
	ConfigPath  string                `json:"config_path"`
	AuditPath   string                `json:"audit_path"`
	Rules       rulesOverview         `json:"rules"`
	Counters    countersOverview      `json:"counters"`
	Events      []services.AuditEvent `json:"events"`
	LastBlocked *services.AuditEvent  `json:"last_blocked,omitempty"`
}

type rulesOverview struct {
	DenyRead []string `json:"deny_read"`
	DenyExec []string `json:"deny_exec"`
	AllowNet []string `json:"allow_net"`
}

type countersOverview struct {
	BlockedTotal int            `json:"blocked_total"`
	BlockedToday int            `json:"blocked_today"`
	RunsTotal    int            `json:"runs_total"`
	ByRule       map[string]int `json:"by_rule"`
	BySource     map[string]int `json:"by_source"`
}

func (s *Server) buildOverview() overview {
	cfgPath, _ := s.configSvc.GlobalConfigPath()
	auditPath, _ := s.auditSvc.Path()
	data := overview{
		ConfigPath: cfgPath,
		AuditPath:  auditPath,
		Rules: rulesOverview{
			DenyRead: []string{},
			DenyExec: []string{},
			AllowNet: []string{},
		},
		Counters: countersOverview{
			ByRule:   map[string]int{"deny_read": 0, "deny_exec": 0, "allow_net": 0},
			BySource: map[string]int{},
		},
	}
	cfg, err := s.configSvc.LoadGlobal()
	if err == nil && cfg != nil {
		data.Initialized = true
		data.Rules = rulesFromConfig(*cfg)
	}
	events, err := s.auditSvc.Recent(200)
	if err == nil {
		data.Events = events
	}
	today := time.Now().Format("2006-01-02")
	for _, event := range data.Events {
		if event.Kind == "run_started" {
			data.Counters.RunsTotal++
			continue
		}
		if event.Kind != "blocked" {
			continue
		}
		data.Counters.BlockedTotal++
		if event.Time.Format("2006-01-02") == today {
			data.Counters.BlockedToday++
		}
		if event.Rule != "" {
			data.Counters.ByRule[event.Rule]++
		}
		if event.Source != "" {
			data.Counters.BySource[event.Source]++
		}
		if data.LastBlocked == nil || event.Time.After(data.LastBlocked.Time) {
			copyEvent := event
			data.LastBlocked = &copyEvent
		}
	}
	sort.SliceStable(data.Events, func(i, j int) bool {
		return data.Events[i].Time.After(data.Events[j].Time)
	})
	if len(data.Events) > 80 {
		data.Events = data.Events[:80]
	}
	return data
}

func rulesFromConfig(cfg domain.Config) rulesOverview {
	return rulesOverview{
		DenyRead: append([]string(nil), cfg.DenyRead...),
		DenyExec: append([]string(nil), cfg.DenyExec...),
		AllowNet: append([]string(nil), cfg.AllowNet...),
	}
}
