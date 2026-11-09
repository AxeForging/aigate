package web

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/AxeForging/aigate/services"
)

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.templates.ExecuteTemplate(w, "layout", s.buildOverview()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleOverview(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.buildOverview())
}

// handleDecisions serves the filterable decisions timeline:
// /api/decisions?identity=work&layer=judge&kind=judge_override&since=24h
func (s *Server) handleDecisions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := services.DecisionFilter{Identity: q.Get("identity"), Layer: q.Get("layer"), Kind: q.Get("kind")}
	if since := q.Get("since"); since != "" {
		d, err := time.ParseDuration(since)
		if err != nil || d <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "since must be a duration like 24h"})
			return
		}
		f.Since = time.Now().Add(-d)
	}
	events, err := s.auditSvc.Recent(2000)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read the audit log"})
		return
	}
	decisions := services.Decisions(events, f)
	if decisions == nil {
		decisions = []services.Decision{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"decisions": decisions})
}

// handleIdentities serves one card per identity.
func (s *Server) handleIdentities(w http.ResponseWriter, _ *http.Request) {
	cfg, err := s.configSvc.LoadGlobal()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"identities": []services.IdentitySummary{}, "initialized": false})
		return
	}
	events, _ := s.auditSvc.Recent(2000)
	ids := services.SummarizeIdentities(cfg, events)
	if ids == nil {
		ids = []services.IdentitySummary{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"identities": ids, "initialized": true})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
