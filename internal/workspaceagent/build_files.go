package workspaceagent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
)

// FileRef names files a build copies from the workspace, as an add_files
// entry in its manifest does: the file at Path, every file under the
// directory at Path, or with Glob, every file Path matches. Path is relative
// to the workspace directory.
//
// Directories are walked as Python's os.walk walks them, without entering
// links to directories, and globs match as glob.glob(recursive=True) does,
// since AIB matches them that way: ** matches any number of directories,
// following links that don't loop, and a wildcard matches a name starting
// with a dot only when the pattern's name starts with one.
type FileRef struct {
	Path string `json:"path"`
	Glob bool   `json:"glob,omitempty"`
}

// ListFilesRequest is the body of POST /files/list.
type ListFilesRequest struct {
	Refs []FileRef `json:"refs"`
}

// ListFilesResponse answers POST /files/list.
type ListFilesResponse struct {
	Files []string `json:"files"`
}

// errOutside marks a directory ref whose real path is outside the workspace.
var errOutside = errors.New("outside the workspace")

// ListFiles returns the regular files refs name, relative to the workspace
// directory, each once and sorted. Links to files are followed, and a file
// whose real path is outside the workspace fails the list, as does a ref that
// names no file: both fail the same way on every retry, so the error is 422
// and names every such file and ref.
func (a *Agent) ListFiles(ctx context.Context, refs []FileRef) ([]string, error) {
	for _, ref := range refs {
		if !fs.ValidPath(ref.Path) || ref.Path == "." || strings.ContainsRune(ref.Path, 0) {
			return nil, apiError(http.StatusBadRequest, "invalid path %q: must be a clean path relative to the workspace", ref.Path)
		}
	}
	a.syncing.Add(1)
	defer a.syncing.Add(-1)
	root, err := filepath.EvalSymlinks(a.workspace)
	if err != nil {
		return nil, err
	}
	found := map[string]bool{}
	var missing, outside []string
	for _, ref := range refs {
		var names []string
		if ref.Glob {
			names, err = glob(ctx, root, ref.Path)
		} else {
			names, err = walk(ctx, root, ref.Path)
		}
		if errors.Is(err, errOutside) {
			outside = append(outside, ref.Path)
			continue
		}
		if err != nil {
			return nil, err
		}
		matched := false
		for _, name := range names {
			regular, within := classify(root, name)
			switch {
			case regular && within:
				found[name] = true
			case regular:
				outside = append(outside, name)
			default:
				continue
			}
			matched = true
		}
		if !matched {
			missing = append(missing, ref.Path)
		}
	}
	var problems []string
	if len(outside) > 0 {
		problems = append(problems, "files outside the workspace: "+strings.Join(outside, ", "))
	}
	if len(missing) > 0 {
		problems = append(problems, "missing workspace files: "+strings.Join(missing, ", "))
	}
	if len(problems) > 0 {
		return nil, apiError(http.StatusUnprocessableEntity, "%s", strings.Join(problems, "; "))
	}
	return slices.Sorted(maps.Keys(found)), nil
}

// classify reports whether name, following links, is a regular file, and
// whether its real path is in root.
func classify(root, name string) (regular, within bool) {
	real, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(name)))
	if err != nil {
		return false, false
	}
	info, err := os.Stat(real)
	if err != nil || !info.Mode().IsRegular() {
		return false, false
	}
	return true, inRoot(root, real)
}

func inRoot(root, real string) bool {
	return real == root || strings.HasPrefix(real, root+string(os.PathSeparator))
}

// absentPath reports an error that means a path names nothing, including one
// that goes through a file.
func absentPath(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR)
}

// walk returns name if it is not a directory, and otherwise every entry under
// it that is not a directory, as os.walk lists them: links name goes through
// are followed, links inside it are listed but not entered.
func walk(ctx context.Context, root, name string) ([]string, error) {
	top := filepath.Join(root, filepath.FromSlash(name))
	info, err := os.Stat(top)
	if absentPath(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{name}, nil
	}
	real, err := filepath.EvalSymlinks(top)
	if err != nil {
		return nil, err
	}
	if !inRoot(root, real) {
		return nil, errOutside
	}
	var names []string
	err = filepath.WalkDir(real, func(p string, entry fs.DirEntry, err error) error {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if err != nil {
			// os.walk skips what it can't list.
			if p == real {
				return err
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(real, p)
		if err != nil {
			return err
		}
		names = append(names, path.Join(name, filepath.ToSlash(rel)))
		return nil
	})
	return names, err
}

// glob returns the names under root that pattern matches, of any type.
func glob(ctx context.Context, root, pattern string) ([]string, error) {
	names := []string{"."}
	segments := strings.Split(pattern, "/")
	for i, segment := range segments {
		last := i == len(segments)-1
		var next []string
		for _, dir := range names {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			switch {
			case segment == "**":
				matches, err := globStar(ctx, root, dir, last)
				if err != nil {
					return nil, err
				}
				next = append(next, matches...)
			case !strings.ContainsAny(segment, "*?["):
				name := path.Join(dir, segment)
				if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(name))); err == nil {
					next = append(next, name)
				}
			default:
				entries, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(dir)))
				if err != nil {
					// Python's glob skips what it can't list.
					continue
				}
				for _, entry := range entries {
					if hidden(entry.Name()) && !hidden(segment) {
						continue
					}
					if matchName(segment, entry.Name()) {
						next = append(next, path.Join(dir, entry.Name()))
					}
				}
			}
		}
		names = next
	}
	return names, nil
}

func hidden(name string) bool { return strings.HasPrefix(name, ".") }

// globStar returns what ** matches in dir: dir itself and every directory
// under it, and with files every other entry too, skipping hidden names. It
// follows links to directories, except one that leads back to a directory it
// is already in, which Python's glob follows until the path is too long.
func globStar(ctx context.Context, root, dir string, files bool) ([]string, error) {
	var matches []string
	inside := map[string]bool{}
	var visit func(name, real string) error
	visit = func(name, real string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries, err := os.ReadDir(real)
		if err != nil {
			return nil
		}
		inside[real] = true
		defer delete(inside, real)
		for _, entry := range entries {
			if hidden(entry.Name()) {
				continue
			}
			child := path.Join(name, entry.Name())
			childReal, isDir := realDir(root, child)
			if !isDir {
				if files {
					matches = append(matches, child)
				}
				continue
			}
			matches = append(matches, child)
			if !inside[childReal] {
				if err := visit(child, childReal); err != nil {
					return err
				}
			}
		}
		return nil
	}
	real, isDir := realDir(root, dir)
	if !isDir {
		return nil, nil
	}
	matches = append(matches, dir)
	err := visit(dir, real)
	return matches, err
}

// realDir returns name's real path and whether it is a directory.
func realDir(root, name string) (string, bool) {
	real, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(name)))
	if err != nil {
		return "", false
	}
	info, err := os.Stat(real)
	return real, err == nil && info.IsDir()
}

// matchName reports whether name matches pattern as Python's fnmatch matches
// it, by rewriting pattern for path.Match: a class negated with ! uses ^, a
// leading ^ in a class is literal, a backslash is literal, and so is a [
// that no ] closes.
func matchName(pattern, name string) bool {
	var b strings.Builder
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch c {
		case '\\':
			b.WriteString(`\\`)
		case '[':
			// fnmatch's rule for where a class ends: a ] right after the
			// [ or the [! is part of the class.
			j := i + 1
			if j < len(pattern) && pattern[j] == '!' {
				j++
			}
			if j < len(pattern) && pattern[j] == ']' {
				j++
			}
			end := strings.IndexByte(pattern[j:], ']')
			if end < 0 {
				b.WriteString(`\[`)
				continue
			}
			class := pattern[i+1 : j+end]
			b.WriteByte('[')
			switch {
			case strings.HasPrefix(class, "!"):
				b.WriteByte('^')
				class = class[1:]
			case strings.HasPrefix(class, "^"):
				b.WriteString(`\^`)
				class = class[1:]
			}
			b.WriteString(escapeClass(class))
			b.WriteByte(']')
			i = j + end
		default:
			b.WriteByte(c)
		}
	}
	matched, err := path.Match(b.String(), name)
	return err == nil && matched
}

// escapeClass escapes what path.Match reads differently in a class: a
// backslash, and a ] or - at either end, which fnmatch takes literally.
func escapeClass(class string) string {
	var b strings.Builder
	for i := 0; i < len(class); i++ {
		c := class[i]
		edge := i == 0 || i == len(class)-1
		if c == '\\' || (edge && (c == ']' || c == '-')) {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	return b.String()
}

// openFile opens the regular file at name in root, following links, and
// refuses one whose real path is outside root. It checks the type before
// opening, so a FIFO doesn't block it.
func openFile(root, name string) (*os.File, os.FileInfo, error) {
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, nil, err
	}
	real, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(path.Clean("/"+name))))
	if err != nil {
		return nil, nil, err
	}
	if !inRoot(root, real) {
		return nil, nil, fs.ErrNotExist
	}
	if info, err := os.Stat(real); err != nil || !info.Mode().IsRegular() {
		return nil, nil, fs.ErrNotExist
	}
	file, err := os.Open(real)
	if err != nil {
		return nil, nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, nil, fs.ErrNotExist
	}
	return file, info, nil
}

func (a *Agent) handleListFiles(w http.ResponseWriter, r *http.Request) {
	var req ListFilesRequest
	if err := decodeFileList(w, r, &req); err != nil {
		writeError(w, err)
		return
	}
	files, err := a.ListFiles(r.Context(), req.Refs)
	writeResult(w, http.StatusOK, ListFilesResponse{Files: files}, err)
}

func (a *Agent) handleGetFile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("path")
	if !fs.ValidPath(name) || name == "." {
		writeError(w, apiError(http.StatusBadRequest, "invalid path %q: must be a clean path relative to the workspace", name))
		return
	}
	a.syncing.Add(1)
	defer a.syncing.Add(-1)
	file, info, err := openFile(a.workspace, name)
	if err != nil {
		writeError(w, apiError(http.StatusNotFound, "no file %s in the workspace", name))
		return
	}
	defer func() { _ = file.Close() }()
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, info.Name(), info.ModTime(), file)
}

// ListFiles returns the files refs name, relative to the workspace.
func (c *Client) ListFiles(ctx context.Context, refs []FileRef) ([]string, error) {
	var resp ListFilesResponse
	err := c.call(ctx, http.MethodPost, "/files/list", ListFilesRequest{Refs: refs}, &resp)
	return resp.Files, err
}

// OpenFile returns the content of the workspace file at name, relative to
// the workspace, for the caller to close.
func (c *Client) OpenFile(ctx context.Context, name string) (io.ReadCloser, error) {
	if !fs.ValidPath(name) || name == "." {
		return nil, fmt.Errorf("invalid workspace file name %q", name)
	}
	segments := strings.Split(name, "/")
	for i, segment := range segments {
		segments[i] = url.PathEscape(segment)
	}
	resp, err := c.request(ctx, http.MethodGet, "/files/"+strings.Join(segments, "/"), nil)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}
