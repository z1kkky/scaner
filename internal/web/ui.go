package web

import (
	"embed"
	"encoding/json"
	"net/http"
	"time"
)

//go:embed ui/index.html ui/app.js ui/style.css
var uiFiles embed.FS

func setUIHeaders(w http.ResponseWriter, contentType string) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func (s *Service) serveIndex(w http.ResponseWriter, _ *http.Request) {
	data, err := uiFiles.ReadFile("ui/index.html")
	if err != nil {
		http.Error(w, "UI unavailable", http.StatusInternalServerError)
		return
	}
	setUIHeaders(w, "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Service) serveAppJS(w http.ResponseWriter, _ *http.Request) {
	s.serveAsset(w, "ui/app.js", "text/javascript; charset=utf-8")
}

func (s *Service) serveStyleCSS(w http.ResponseWriter, _ *http.Request) {
	s.serveAsset(w, "ui/style.css", "text/css; charset=utf-8")
}

func (s *Service) serveAsset(w http.ResponseWriter, name, contentType string) {
	data, err := uiFiles.ReadFile(name)
	if err != nil {
		http.Error(w, "UI asset not found", http.StatusNotFound)
		return
	}
	setUIHeaders(w, contentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

type demoReport struct {
	Engine     string              `json:"engine"`
	Simulation bool                `json:"simulation"`
	Disclaimer string              `json:"disclaimer"`
	Score      int                 `json:"score"`
	Grade      string              `json:"grade"`
	Findings   []map[string]string `json:"findings"`
}

func deterministicDemoReport() json.RawMessage {
	report := demoReport{
		Engine:     "Scaner — демонстрационный режим",
		Simulation: true,
		Disclaimer: "Учебный пример. Это не результат реального сканирования; сетевые проверки не выполнялись.",
		Score:      72,
		Grade:      "C",
		Findings: []map[string]string{
			{"template_id": "demo-csp", "check": "headers", "title": "Не настроена политика CSP", "severity": "medium", "matched_at": "https://demo.invalid/", "description": "Без CSP браузеру сложнее ограничить загрузку нежелательных скриптов.", "fix": "Настройте Content-Security-Policy с учётом ресурсов сайта и повторите проверку."},
			{"template_id": "demo-port", "check": "ports", "title": "Открыт дополнительный сетевой порт", "severity": "low", "matched_at": "demo.invalid:8080/tcp", "description": "На дополнительном порту может быть доступен сервис, который не предназначен для посетителей.", "fix": "Уточните назначение порта 8080 и ограничьте доступ, если сервис не должен быть публичным."},
		},
	}
	b, _ := json.Marshal(report)
	return b
}

func (s *Service) createDemoJob(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	if s.storageErr != "" {
		http.Error(w, "local storage is unavailable; restart the service after resolving the storage error", http.StatusServiceUnavailable)
		return
	}
	id, err := randomID()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	now := time.Now().UTC()
	job := Job{
		ID: id, Simulation: true, Status: "completed",
		CreatedAt: now, FinishedAt: now,
		Result: deterministicDemoReport(),
	}
	s.state.Jobs[id] = job
	if err = s.persistLocked(); err != nil {
		delete(s.state.Jobs, id)
		http.Error(w, "demo history could not be saved", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, job)
}
