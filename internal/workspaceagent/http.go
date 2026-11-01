package workspaceagent

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
)

// CreateRequest is the body of POST /runs.
type CreateRequest struct {
	ID      string  `json:"id"`
	Command string  `json:"command"`
	Options Options `json:"options"`
}

// VersionResponse is the body of GET /version.
type VersionResponse struct {
	Protocol int `json:"protocol"`
}

const logReadBytes = 1 << 20

// Handler serves the agent API. Every endpoint except /healthz requires
// token as a bearer token.
func (a *Agent) Handler(token string) http.Handler {
	api := http.NewServeMux()
	api.HandleFunc("GET /version", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, VersionResponse{Protocol: ProtocolVersion})
	})
	api.HandleFunc("POST /runs", a.handleCreate)
	api.HandleFunc("GET /runs", a.handleList)
	api.HandleFunc("GET /runs/{id}", func(w http.ResponseWriter, r *http.Request) {
		run, err := a.Get(r.PathValue("id"))
		writeResult(w, http.StatusOK, run, err)
	})
	api.HandleFunc("GET /runs/{id}/logs", a.handleLogs)
	api.HandleFunc("POST /runs/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		run, err := a.Cancel(r.PathValue("id"))
		writeResult(w, http.StatusOK, run, err)
	})
	api.HandleFunc("DELETE /runs/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := a.Delete(r.PathValue("id")); err != nil {
			writeError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.Handle("/", requireToken(token, api))
	return mux
}

func requireToken(token string, next http.Handler) http.Handler {
	want := []byte("Bearer " + token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), want) != 1 {
			writeError(w, apiError(http.StatusUnauthorized, "unauthorized"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// maxCreateBytes leaves room for a 64 KiB command, the build API's limit,
// with every byte JSON-escaped to six.
const maxCreateBytes = 512 << 10

func (a *Agent) handleCreate(w http.ResponseWriter, r *http.Request) {
	var req CreateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxCreateBytes)).Decode(&req); err != nil {
		writeError(w, apiError(http.StatusBadRequest, "invalid JSON request"))
		return
	}
	run, created, err := a.Create(req.ID, req.Command, req.Options)
	status := http.StatusOK
	if created {
		status = http.StatusAccepted
	}
	writeResult(w, status, run, err)
}

func (a *Agent) handleList(w http.ResponseWriter, r *http.Request) {
	offset, offsetErr := strconv.Atoi(queryDefault(r, "offset", "0"))
	limit, limitErr := strconv.Atoi(queryDefault(r, "limit", "100"))
	if offsetErr != nil || limitErr != nil || offset < 0 || limit < 1 || limit > 100 {
		writeError(w, apiError(http.StatusBadRequest, "offset must be non-negative and limit must be between 1 and 100"))
		return
	}
	runs, err := a.List(offset, limit)
	writeResult(w, http.StatusOK, runs, err)
}

// handleLogs streams raw output from an absolute offset. Without follow it
// stops at the end of the output that existed when the request arrived; with
// follow it streams until the run ends or the client goes away. The trailers
// report the run's final state, or why the stream stopped early.
func (a *Agent) handleLogs(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	offset, err := strconv.ParseInt(queryDefault(r, "offset", "0"), 10, 64)
	if err != nil || offset < 0 {
		writeError(w, apiError(http.StatusBadRequest, "offset must be a non-negative byte offset"))
		return
	}
	// A bare ?follow is present with an empty value and enables following.
	follow := r.URL.Query().Has("follow")
	if value := r.URL.Query().Get("follow"); value != "" {
		if follow, err = strconv.ParseBool(value); err != nil {
			writeError(w, apiError(http.StatusBadRequest, "follow must be a boolean"))
			return
		}
	}
	offset, run, err := a.openLog(id, offset)
	if err != nil {
		writeError(w, err)
		return
	}
	end := run.LogBytes
	header := w.Header()
	header.Set("Content-Type", "text/plain; charset=utf-8")
	header.Set("Cache-Control", "no-store")
	header.Set("X-Log-Offset", strconv.FormatInt(offset, 10))
	header.Set("Trailer", "X-Log-Error, X-Run-Status, X-Run-Exit-Code")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	for {
		data, current, changed, err := a.readLog(id, offset, logReadBytes)
		if err != nil {
			header.Set("X-Log-Error", err.Error())
			return
		}
		run = current
		if !follow {
			data = data[:min(int64(len(data)), max(0, end-offset))]
		}
		if len(data) > 0 {
			if _, err := w.Write(data); err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
			offset += int64(len(data))
		}
		if (!follow && offset >= end) || (!live(run.Status) && offset >= run.LogBytes) {
			break
		}
		if len(data) == 0 {
			select {
			case <-changed:
			case <-r.Context().Done():
				return
			}
		}
	}
	header.Set("X-Run-Status", run.Status)
	if run.ExitCode != nil {
		header.Set("X-Run-Exit-Code", strconv.Itoa(*run.ExitCode))
	}
}

func queryDefault(r *http.Request, key, fallback string) string {
	if value := r.URL.Query().Get(key); value != "" {
		return value
	}
	return fallback
}

func writeResult(w http.ResponseWriter, status int, body any, err error) {
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, status, body)
}

func writeError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	var apiErr *Error
	if errors.As(err, &apiErr) {
		status = apiErr.Code
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
