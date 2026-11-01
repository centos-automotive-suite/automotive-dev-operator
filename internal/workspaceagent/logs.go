package workspaceagent

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const segmentSize = 1 << 20

func segmentPath(dir string, first int64) string {
	return filepath.Join(dir, fmt.Sprintf("%020d.log", first))
}

// logWriter appends output to segment files named by their absolute offset.
// Whole segments are deleted once they fall outside the newest limit bytes, so
// the leading segment may hold a prefix that is no longer readable.
type logWriter struct {
	dir      string
	limit    int64
	chunk    int64
	oldest   int64
	position int64
	file     *os.File
}

func newLogWriter(dir string, limit int64) (*logWriter, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &logWriter{dir: dir, limit: limit, chunk: min(segmentSize, limit)}, nil
}

func (w *logWriter) write(data []byte) error {
	for len(data) > 0 {
		room := w.chunk - w.position%w.chunk
		if w.file == nil || room == w.chunk {
			if w.file != nil {
				_ = w.file.Close()
			}
			f, err := os.OpenFile(segmentPath(w.dir, w.position), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
			if err != nil {
				w.file = nil
				return err
			}
			w.file = f
		}
		n, err := w.file.Write(data[:min(room, int64(len(data)))])
		w.position += int64(n)
		data = data[n:]
		if err != nil {
			return err
		}
		for w.oldest+w.chunk <= w.position-w.limit {
			if err := os.Remove(segmentPath(w.dir, w.oldest)); err != nil && !os.IsNotExist(err) {
				return err
			}
			w.oldest += w.chunk
		}
	}
	return nil
}

// close trims the readable prefix out of the leading segment, so a finished
// log fits its limit exactly even when the limit equals the log budget.
func (w *logWriter) close() error {
	if w.file != nil {
		if err := w.file.Close(); err != nil {
			return err
		}
		w.file = nil
	}
	start := max(0, w.position-w.limit)
	if w.oldest >= start {
		return nil
	}
	old := segmentPath(w.dir, w.oldest)
	data, err := os.ReadFile(old)
	if err != nil {
		return err
	}
	if err := os.WriteFile(segmentPath(w.dir, start), data[start-w.oldest:], 0o600); err != nil {
		return err
	}
	return os.Remove(old)
}

type segment struct {
	first, size int64
	path        string
}

func listSegments(dir string) ([]segment, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var segments []segment
	for _, entry := range entries {
		name, ok := strings.CutSuffix(entry.Name(), ".log")
		if !ok {
			continue
		}
		first, err := strconv.ParseInt(name, 10, 64)
		if err != nil {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		segments = append(segments, segment{first: first, size: info.Size(), path: filepath.Join(dir, entry.Name())})
	}
	sort.Slice(segments, func(i, j int) bool { return segments[i].first < segments[j].first })
	return segments, nil
}

// logWindow is the readable range [start, end) of a run's output.
type logWindow struct {
	start, end int64
	segments   []segment
}

func (w logWindow) stored() int64 {
	var total int64
	for _, s := range w.segments {
		total += s.size
	}
	return total
}

// read returns up to limit bytes from offset, which must be in the window.
func (w logWindow) read(offset, limit int64) ([]byte, error) {
	var data []byte
	for _, s := range w.segments {
		if s.first+s.size <= offset {
			continue
		}
		f, err := os.Open(s.path)
		if err != nil {
			return nil, err
		}
		chunk := make([]byte, min(limit-int64(len(data)), s.first+s.size-offset))
		n, err := f.ReadAt(chunk, offset-s.first)
		_ = f.Close()
		if err != nil && err != io.EOF {
			return nil, err
		}
		data = append(data, chunk[:n]...)
		offset += int64(n)
		if int64(len(data)) == limit || n < len(chunk) {
			break
		}
	}
	return data, nil
}
