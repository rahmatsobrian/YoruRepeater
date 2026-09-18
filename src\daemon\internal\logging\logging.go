// Package logging provides Yoru's structured, rotating, secret-safe logger.
//
// Guarantees that the rest of the daemon relies on:
//   - passphrases, PSKs, tokens, session ids and (optionally) MACs never reach
//     disk or the log API,
//   - disk usage is bounded by MaxBytes*MaxFiles with rotation,
//   - recent entries live in an in-memory ring buffer so the WebUI never needs
//     file access,
//   - it is safe for concurrent use from monitors, the API and child processes.
package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Level is a log severity.
type Level int

// Severity levels.
const (
	Debug Level = iota
	Info
	Warn
	Error
)

// String returns the wire representation of the level.
func (l Level) String() string {
	switch l {
	case Debug:
		return "DEBUG"
	case Warn:
		return "WARN"
	case Error:
		return "ERROR"
	default:
		return "INFO"
	}
}

// ParseLevel maps configuration text to a Level, defaulting to Info.
func ParseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug", "trace", "verbose":
		return Debug
	case "warn", "warning":
		return Warn
	case "error", "fatal", "critical":
		return Error
	default:
		return Info
	}
}

// Record is one log entry; it doubles as the /api/v1/logs wire format.
type Record struct {
	Time  int64  `json:"t"`
	Level string `json:"level"`
	Src   string `json:"src"`
	Msg   string `json:"msg"`
}

var credentialRules = []struct {
	re   *regexp.Regexp
	mask string
}{
	{regexp.MustCompile(`(?i)(passphrase|password|passwd|psk|wpa_key|wep_key|secret|token|credential|authorization)(["']?\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s,;}\]]+)`), "$1$2[REDACTED]"},
	{regexp.MustCompile(`(?im)^(\s*(?:wpa_passphrase|passphrase|wep_key\d*)\s*=\s*).*?$`), "$1[REDACTED]"},
	{regexp.MustCompile(`(?i)(yorusid|session[_-]?id)([=:]\s*)([A-Za-z0-9+/_=.~-]+)`), "$1$2[REDACTED]"},
}

var macRule = regexp.MustCompile(`\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b|\b(?:[0-9A-Fa-f]{2}:){7}[0-9A-Fa-f]{2}\b`)

// Redact strips credential material from arbitrary text.
func Redact(s string) string {
	for _, r := range credentialRules {
		s = r.re.ReplaceAllString(s, r.mask)
	}
	return s
}

// MaskMAC replaces MAC addresses with a stable short fingerprint so that the
// UI can still correlate a device without disclosing its identity.
func MaskMAC(mac string) string {
	mac = strings.ToLower(strings.ReplaceAll(mac, ":", ""))
	if len(mac) < 8 {
		return "**:**:**:**:**:**"
	}
	return fmt.Sprintf("%s:**:**:**:**:%s", mac[0:2], mac[len(mac)-2:])
}

// Options configures a Logger.
type Options struct {
	Path     string
	Level    Level
	MaxBytes int64
	MaxFiles int
	RingSize int
	Stderr   bool
	MaskMACs bool
}

// Logger writes to file + ring buffer. The zero value is not usable; call New.
type Logger struct {
	mu       sync.Mutex
	opts     Options
	file     *os.File
	size     int64
	ring     []Record
	pos      int
	filled   bool
	fileErr  error
	diskDrop uint64
	written  uint64
}

// New prepares a logger. An unwritable log path is not fatal: the daemon keeps
// running with the in-memory buffer and reports the condition via FileErr().
func New(opts Options) *Logger {
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = 1 << 20
	}
	if opts.MaxFiles <= 0 {
		opts.MaxFiles = 3
	}
	if opts.RingSize <= 0 {
		opts.RingSize = 1000
	}
	l := &Logger{opts: opts, ring: make([]Record, opts.RingSize)}
	if opts.Path != "" {
		if err := os.MkdirAll(filepath.Dir(opts.Path), 0700); err != nil {
			l.fileErr = fmt.Errorf("log dir: %w", err)
		} else {
			f, err := os.OpenFile(opts.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
			if err != nil {
				l.fileErr = fmt.Errorf("open log: %w", err)
			} else {
				l.file = f
				if st, serr := f.Stat(); serr == nil {
					l.size = st.Size()
				}
			}
		}
	}
	return l
}

// FileErr reports why file logging is unavailable, if it is.
func (l *Logger) FileErr() error { return l.fileErr }

// SetLevel changes verbosity at runtime (Settings -> debug logging).
func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	l.opts.Level = level
	l.mu.Unlock()
}

// Level reports the current verbosity.
func (l *Logger) Level() Level {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.opts.Level
}

func (l *Logger) log(level Level, src, format string, args ...any) {
	l.mu.Lock()
	if level < l.opts.Level {
		l.mu.Unlock()
		return
	}
	msg := fmt.Sprintf(format, args...)
	msg = Redact(msg)
	if l.opts.MaskMACs {
		msg = macRule.ReplaceAllStringFunc(msg, func(s string) string { return MaskMAC(s) })
	}
	rec := Record{Time: time.Now().UnixMilli(), Level: level.String(), Src: src, Msg: strings.ReplaceAll(msg, "\n", " ")}
	l.ring[l.pos] = rec
	l.pos++
	if l.pos >= len(l.ring) {
		l.pos = 0
		l.filled = true
	}
	line := fmt.Sprintf("%s [%s] %s: %s\n", time.Now().Format("2006-01-02 15:04:05"), rec.Level, rec.Src, rec.Msg)
	if l.opts.Stderr {
		_, _ = os.Stderr.WriteString(line)
	}
	if l.file != nil {
		n, err := l.file.WriteString(line)
		if err != nil {
			l.fileErr = fmt.Errorf("write log: %w", err)
			_ = l.file.Close()
			l.file = nil
		} else {
			l.written += uint64(n)
			l.size += int64(n)
			if l.size >= l.opts.MaxBytes {
				l.rotateLocked()
			}
		}
	} else {
		l.diskDrop++
	}
	l.mu.Unlock()
}

// rotateLocked shifts yoru.log -> yoru.log.1 -> ... and drops the oldest.
// Callers must hold l.mu.
func (l *Logger) rotateLocked() {
	if l.file != nil {
		_ = l.file.Close()
		l.file = nil
	}
	base := l.opts.Path
	for i := l.opts.MaxFiles - 1; i >= 1; i-- {
		from := fmt.Sprintf("%s.%d", base, i-1)
		to := fmt.Sprintf("%s.%d", base, i)
		if i == l.opts.MaxFiles-1 {
			_ = os.Remove(to)
		}
		if err := os.Rename(from, to); err != nil && !os.IsNotExist(err) {
			l.fileErr = fmt.Errorf("rotate: %w", err)
		}
	}
	f, err := os.OpenFile(base, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		l.fileErr = fmt.Errorf("reopen log: %w", err)
		return
	}
	l.file = f
	l.size = 0
}

// Debugf logs at debug severity.
func (l *Logger) Debugf(src, format string, args ...any) { l.log(Debug, src, format, args...) }

// Infof logs at info severity.
func (l *Logger) Infof(src, format string, args ...any) { l.log(Info, src, format, args...) }

// Warnf logs at warning severity.
func (l *Logger) Warnf(src, format string, args ...any) { l.log(Warn, src, format, args...) }

// Errorf logs at error severity.
func (l *Logger) Errorf(src, format string, args ...any) { l.log(Error, src, format, args...) }

// Tail returns up to n most recent records, oldest first.
func (l *Logger) Tail(n int, minLevel Level, search string) []Record {
	l.mu.Lock()
	defer l.mu.Unlock()
	count := l.pos
	if l.filled {
		count = len(l.ring)
	}
	if n <= 0 || n > count {
		n = count
	}
	out := make([]Record, 0, n)
	needle := strings.ToLower(search)
	for i := count - n; i < count; i++ {
		idx := i
		if l.filled {
			idx = (i + len(l.ring)) % len(l.ring)
		}
		rec := l.ring[idx]
		if ParseLevel(rec.Level) < minLevel {
			continue
		}
		if needle != "" && !strings.Contains(strings.ToLower(rec.Msg+" "+rec.Src), needle) {
			continue
		}
		out = append(out, rec)
	}
	return out
}

// Stats exposes logger health for the diagnostics page.
func (l *Logger) Stats() map[string]any {
	l.mu.Lock()
	defer l.mu.Unlock()
	m := map[string]any{
		"path":       l.opts.Path,
		"fileOk":     l.file != nil,
		"sizeBytes":  l.size,
		"maxBytes":   l.opts.MaxBytes,
		"maxFiles":   l.opts.MaxFiles,
		"ringSize":   len(l.ring),
		"buffered":   l.ringBufferedLocked(),
		"lineCount":  l.written,
		"memOnly":    l.diskDrop,
		"level":      l.opts.Level.String(),
		"macMasking": l.opts.MaskMACs,
	}
	if l.fileErr != nil {
		m["error"] = l.fileErr.Error()
	}
	return m
}

func (l *Logger) ringBufferedLocked() int {
	if l.filled {
		return len(l.ring)
	}
	return l.pos
}

// Close flushes and closes the log file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		err := l.file.Close()
		l.file = nil
		return err
	}
	return nil
}
