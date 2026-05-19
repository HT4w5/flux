package index

import (
	"context"
	"crypto/rand"
	mrand "math/rand/v2"
	"os"
	"path"
	"path/filepath"
	"testing"
)

// ---------- TestLocalDriver_SimpleGetSize ----------

func TestLocalDriver_SimpleGetSize(t *testing.T) {
	dir := t.TempDir()

	// Create a file with known content
	content := []byte("hello world")
	filePath := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(filePath, content, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Create driver with one route: /files -> dir
	drv := NewLocalDriver(map[string]string{
		"/files": dir,
	})

	ctx := context.Background()
	size, err := drv.Query(ctx, "/files/file.txt")
	if err != nil {
		t.Fatalf("Query: unexpected error: %v", err)
	}
	if size != int64(len(content)) {
		t.Errorf("Query size = %d, want %d", size, len(content))
	}
}

// ---------- TestLocalDriver_PrefixRouting ----------

func TestLocalDriver_PrefixRouting(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	// Create files with distinct content sizes
	const content1 = "short"
	const content2 = "a much longer file content"
	if err := os.WriteFile(filepath.Join(dir1, "shared.txt"), []byte(content1), 0o644); err != nil {
		t.Fatalf("WriteFile dir1: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir2, "shared.txt"), []byte(content2), 0o644); err != nil {
		t.Fatalf("WriteFile dir2: %v", err)
	}
	// File only in dir2
	const content3 = "v2 only"
	if err := os.WriteFile(filepath.Join(dir2, "only.txt"), []byte(content3), 0o644); err != nil {
		t.Fatalf("WriteFile dir2 only: %v", err)
	}

	// Routes: /app -> dir1, /app/v2 -> dir2 (longer prefix should win)
	drv := NewLocalDriver(map[string]string{
		"/app":    dir1,
		"/app/v2": dir2,
	})

	ctx := context.Background()

	tests := []struct {
		name string
		url  string
		want int64
	}{
		{"/app/shared.txt -> dir1", "/app/shared.txt", int64(len(content1))},
		{"/app/v2/shared.txt -> dir2", "/app/v2/shared.txt", int64(len(content2))},
		{"/app/v2/only.txt -> dir2", "/app/v2/only.txt", int64(len(content3))},
		{"/app/only.txt -> not found (only in dir2)", "/app/only.txt", notFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			size, err := drv.Query(ctx, tt.url)
			if err != nil {
				t.Fatalf("Query(%q): unexpected error: %v", tt.url, err)
			}
			if size != tt.want {
				t.Errorf("Query(%q) size = %d, want %d", tt.url, size, tt.want)
			}
		})
	}
}

// ---------- TestLocalDriver_BadURLs ----------

func TestLocalDriver_BadURLs(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte("data"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	drv := NewLocalDriver(map[string]string{
		"/": dir,
	})

	ctx := context.Background()

	tests := []struct {
		name    string
		url     string
		wantErr bool // true -> ErrBadURL
	}{
		{"no leading slash", "foo", true},
		{"empty string", "", true},
		{"relative parent traversal", "../bar", true},
		{"parent traversal normalized", "/../file.txt", false}, // path.Clean -> /file.txt
		{"double slashes normalized", "//file.txt", false},     // path.Clean -> /file.txt
		{"trailing slash normalized", "/file.txt/", false},     // path.Clean -> /file.txt
		{"dot segment normalized", "/./file.txt", false},       // path.Clean -> /file.txt
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := drv.Query(ctx, tt.url)
			if tt.wantErr {
				if err != ErrBadURL {
					t.Errorf("Query(%q) error = %v, want ErrBadURL", tt.url, err)
				}
			} else {
				if err != nil {
					t.Errorf("Query(%q): unexpected error: %v", tt.url, err)
				}
			}
		})
	}
}

// ---------- TestLocalDriver_NotFound ----------

func TestLocalDriver_NotFound(t *testing.T) {
	dir := t.TempDir()
	// Create a directory with no files
	subDir := filepath.Join(dir, "subdir")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "exists.txt"), []byte("data"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	drv := NewLocalDriver(map[string]string{
		"/files": dir,
	})

	ctx := context.Background()

	tests := []struct {
		name string
		url  string
	}{
		{"no matching route", "/other/missing.txt"},
		{"file not on disk", "/files/missing.txt"},
		{"path is a directory", "/files/subdir"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			size, err := drv.Query(ctx, tt.url)
			if err != nil {
				t.Fatalf("Query(%q): unexpected error: %v", tt.url, err)
			}
			if size != notFound {
				t.Errorf("Query(%q) size = %d, want notFound (%d)", tt.url, size, notFound)
			}
		})
	}
}

// ---------- TestLocalDriver_EmptyRoutes ----------

func TestLocalDriver_EmptyRoutes(t *testing.T) {
	drv := NewLocalDriver(map[string]string{})

	ctx := context.Background()
	size, err := drv.Query(ctx, "/anything/file.txt")
	if err != nil {
		t.Fatalf("Query: unexpected error: %v", err)
	}
	if size != notFound {
		t.Errorf("Query size = %d, want notFound (%d)", size, notFound)
	}
}

// ---------- TestLocalDriver_RandomFiles ----------

func TestLocalDriver_RandomFiles(t *testing.T) {
	const (
		numFiles       = 200
		numMissing     = 50
		maxFileSize    = 1 << 20 // 1 MiB
		maxSubDirs     = 4
		maxSubDirDepth = 3
	)

	rng := mrand.New(mrand.NewPCG(114514, 1919810))

	// Create 3 temp dirs with distinct route prefixes
	type route struct {
		prefix string
		dir    string
	}
	routes := []route{
		{"/a", t.TempDir()},
		{"/b", t.TempDir()},
		{"/c", t.TempDir()},
	}

	routeMap := make(map[string]string, len(routes))
	for _, r := range routes {
		routeMap[r.prefix] = r.dir
	}

	// Generate random files
	expected := make(map[string]int64, numFiles)
	for i := 0; i < numFiles; i++ {
		// Pick a random route
		rt := routes[rng.IntN(len(routes))]

		// Generate random subdirectory depth
		depth := rng.IntN(maxSubDirDepth)
		subPath := ""
		for d := 0; d < depth; d++ {
			subPath = filepath.Join(subPath, randomName(rng, 8))
		}
		fullDir := filepath.Join(rt.dir, subPath)
		if err := os.MkdirAll(fullDir, 0o755); err != nil {
			t.Fatalf("MkdirAll %q: %v", fullDir, err)
		}

		// Generate random file
		fileName := randomName(rng, 12) + ".dat"
		filePath := filepath.Join(fullDir, fileName)

		// Random size 1..maxFileSize
		fileSize := rng.Int64N(maxFileSize) + 1

		// Write random content (read up to fileSize from crypto/rand)
		content := make([]byte, fileSize)
		if _, err := rand.Read(content); err != nil {
			t.Fatalf("rand.Read: %v", err)
		}
		if err := os.WriteFile(filePath, content, 0o644); err != nil {
			t.Fatalf("WriteFile %q: %v", filePath, err)
		}

		// Build URL path: <route prefix>/<subpath>/<filename>
		urlPath := path.Join(rt.prefix, subPath, fileName)
		expected[urlPath] = fileSize
	}

	// Build the driver
	drv := NewLocalDriver(routeMap)
	ctx := context.Background()

	// Verify all expected files
	for urlPath, wantSize := range expected {
		size, err := drv.Query(ctx, urlPath)
		if err != nil {
			t.Errorf("Query(%q): unexpected error: %v", urlPath, err)
			continue
		}
		if size != wantSize {
			t.Errorf("Query(%q) size = %d, want %d", urlPath, size, wantSize)
		}
	}

	// Generate and verify random non-existent paths
	seen := make(map[string]bool, numMissing)
	for i := 0; i < numMissing; i++ {
		rt := routes[rng.IntN(len(routes))]
		urlPath := path.Join(rt.prefix, randomName(rng, 16)+".missing")
		// Ensure it's not in expected
		if _, ok := expected[urlPath]; ok {
			continue
		}
		seen[urlPath] = true
	}
	for urlPath := range seen {
		size, err := drv.Query(ctx, urlPath)
		if err != nil {
			t.Errorf("Query(%q): unexpected error: %v", urlPath, err)
			continue
		}
		if size != notFound {
			t.Errorf("Query(%q) size = %d, want notFound (%d)", urlPath, size, notFound)
		}
	}
}

// randomName generates a random alphanumeric name of the given length.
func randomName(rng *mrand.Rand, n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[rng.IntN(len(alphabet))]
	}
	return string(b)
}
