package api

import (
	"bytes"
	"io"
	"io/fs"
	"strings"
	"sync"
	"time"
)

// assetIndex is the authoritative list of servable files, built once from the
// embedded bundle at startup. A request for anything not in this index is a 404
// regardless of path tricks, so the static handler has no filesystem surface.
var (
	assetOnce sync.Once
	assetSet  map[string]bool
)

func buildAssetIndex() {
	assetSet = map[string]bool{}
	_ = fs.WalkDir(distFS, "dist", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d == nil || d.IsDir() {
			return nil
		}
		name := strings.TrimPrefix(p, "dist/")
		assetSet[name] = true
		return nil
	})
}

func embedded(name string) bool {
	assetOnce.Do(buildAssetIndex)
	return assetSet[name]
}

// EmbeddedFiles lists the bundle for the diagnostics page.
func EmbeddedFiles() []string {
	assetOnce.Do(buildAssetIndex)
	out := make([]string, 0, len(assetSet))
	for k := range assetSet {
		out = append(out, k)
	}
	return out
}

// bytesReaderAt adapts a []byte for http.ServeContent.
func bytesReaderAt(b []byte) io.ReadSeeker {
	return bytes.NewReader(b)
}

// tickerLoop runs fn on an interval until the returned stop is called. It is
// used by the monitors so a slow read can never overlap with itself: the next
// tick is scheduled after the previous one finishes.
func tickerLoop(interval time.Duration, stop <-chan struct{}, fn func()) (done chan struct{}) {
	done = make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				fn()
			}
		}
	}()
	return done
}
