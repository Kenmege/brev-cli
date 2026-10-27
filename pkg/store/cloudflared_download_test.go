package store

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The tests in this file never touch the network: they point the package
// download hooks at a local httptest server serving synthetic assets whose
// sha256 matches synthetic pins.

var cloudflaredTestPlatforms = []struct{ goos, goarch string }{
	{"linux", "amd64"},
	{"linux", "arm64"},
	{"darwin", "amd64"},
	{"darwin", "arm64"},
}

type cloudflaredTestEnv struct {
	cl         Cloudflared
	fs         afero.Fs
	binaryPath string
	executable []byte
	requests   *int32
}

func sha256Hex(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// cloudflaredFixture builds the synthetic release asset for a platform: a
// plain executable for linux and a tar.gz archive holding a single
// "cloudflared" executable for darwin, mirroring the real release layout.
func cloudflaredFixture(t *testing.T, goos, goarch string) (assetName string, asset, executable []byte) {
	t.Helper()
	executable = []byte(fmt.Sprintf("synthetic cloudflared executable %s/%s", goos, goarch))
	if goos != "darwin" {
		return fmt.Sprintf("cloudflared-linux-%s", goarch), executable, executable
	}
	var buf bytes.Buffer
	gzipWriter := gzip.NewWriter(&buf)
	tarWriter := tar.NewWriter(gzipWriter)
	err := tarWriter.WriteHeader(&tar.Header{Name: "cloudflared", Mode: 0o755, Size: int64(len(executable))})
	require.NoError(t, err)
	_, err = tarWriter.Write(executable)
	require.NoError(t, err)
	require.NoError(t, tarWriter.Close())
	require.NoError(t, gzipWriter.Close())
	return fmt.Sprintf("cloudflared-darwin-%s.tgz", goarch), buf.Bytes(), executable
}

// newCloudflaredTestEnv installs synthetic pins for goos/goarch and points
// the downloader at a local httptest server. serve == nil serves the correct
// asset; otherwise it customizes the response. All package hooks are
// restored when the test ends.
func newCloudflaredTestEnv(t *testing.T, goos, goarch string, serve func(w http.ResponseWriter, asset []byte)) *cloudflaredTestEnv {
	t.Helper()
	assetName, asset, executable := cloudflaredFixture(t, goos, goarch)

	requests := new(int32)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(requests, 1)
		if r.URL.Path != "/"+CloudflaredVersion+"/"+assetName {
			http.NotFound(w, r)
			return
		}
		if serve != nil {
			serve(w, asset)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(asset)
	}))
	t.Cleanup(server.Close)

	prevBase, prevPins, prevGOOS, prevGOARCH := cloudflaredBaseURL, cloudflaredPins, cloudflaredGOOS, cloudflaredGOARCH
	cloudflaredBaseURL = server.URL
	cloudflaredPins = map[string]cloudflaredPin{
		goos + "-" + goarch: {
			AssetName:        assetName,
			ArchiveSha256:    sha256Hex(asset),
			ExecutableSha256: sha256Hex(executable),
		},
	}
	cloudflaredGOOS, cloudflaredGOARCH = goos, goarch
	t.Cleanup(func() {
		cloudflaredBaseURL = prevBase
		cloudflaredPins = prevPins
		cloudflaredGOOS = prevGOOS
		cloudflaredGOARCH = prevGOARCH
	})

	memfs := afero.NewMemMapFs()
	fsStore := NewBasicStore().WithFileSystem(memfs)
	t.Setenv("HOME", t.TempDir())
	binaryPath, err := fsStore.GetBrevCloudflaredBinaryPath()
	require.NoError(t, err)

	return &cloudflaredTestEnv{
		cl:         NewCloudflare(fsStore),
		fs:         memfs,
		binaryPath: binaryPath,
		executable: executable,
		requests:   requests,
	}
}

func writeExistingCloudflaredBinary(t *testing.T, fsys afero.Fs, binaryPath string, content []byte) {
	t.Helper()
	require.NoError(t, fsys.MkdirAll(filepath.Dir(binaryPath), 0o755))
	require.NoError(t, afero.WriteFile(fsys, binaryPath, content, 0o755))
}

// assertOnlyBinaryInstalled fails unless the binary's directory contains the
// binary and nothing else: no staging files may be left behind.
func assertOnlyBinaryInstalled(t *testing.T, fsys afero.Fs, binaryPath string) {
	t.Helper()
	entries, err := afero.ReadDir(fsys, filepath.Dir(binaryPath))
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	assert.Equal(t, []string{filepath.Base(binaryPath)}, names, "no staging files may be left behind")
}

func assertCloudflaredBinaryMode(t *testing.T, fsys afero.Fs, binaryPath string) {
	t.Helper()
	info, err := fsys.Stat(binaryPath)
	require.NoError(t, err)
	assert.Equal(t, fs.FileMode(0o755), info.Mode().Perm(), "installed binary must be executable")
}

func TestDownloadCloudflaredBinaryIfItDNE_InstallsOrRefreshes(t *testing.T) {
	cases := []struct {
		name     string
		existing []byte // nil = no binary present
	}{
		{name: "missing binary is installed"},
		{name: "stale binary is replaced", existing: []byte("stale cloudflared binary")},
	}
	for _, platform := range cloudflaredTestPlatforms {
		for _, tc := range cases {
			t.Run(platform.goos+"-"+platform.goarch+"/"+tc.name, func(t *testing.T) {
				env := newCloudflaredTestEnv(t, platform.goos, platform.goarch, nil)
				if tc.existing != nil {
					writeExistingCloudflaredBinary(t, env.fs, env.binaryPath, tc.existing)
				}

				require.NoError(t, env.cl.DownloadCloudflaredBinaryIfItDNE())

				got, err := afero.ReadFile(env.fs, env.binaryPath)
				require.NoError(t, err)
				assert.Equal(t, string(env.executable), string(got), "installed binary must be the pinned executable")
				assert.Equal(t, int32(1), atomic.LoadInt32(env.requests))
				assertOnlyBinaryInstalled(t, env.fs, env.binaryPath)
				assertCloudflaredBinaryMode(t, env.fs, env.binaryPath)
			})
		}
	}
}

func TestDownloadCloudflaredBinaryIfItDNE_KeepsCurrentBinaryWithoutDownload(t *testing.T) {
	for _, platform := range cloudflaredTestPlatforms {
		t.Run(platform.goos+"-"+platform.goarch, func(t *testing.T) {
			env := newCloudflaredTestEnv(t, platform.goos, platform.goarch, nil)
			writeExistingCloudflaredBinary(t, env.fs, env.binaryPath, env.executable)

			require.NoError(t, env.cl.DownloadCloudflaredBinaryIfItDNE())

			got, err := afero.ReadFile(env.fs, env.binaryPath)
			require.NoError(t, err)
			assert.Equal(t, string(env.executable), string(got))
			assert.Equal(t, int32(0), atomic.LoadInt32(env.requests), "a current binary must not be re-downloaded")
			assertOnlyBinaryInstalled(t, env.fs, env.binaryPath)
		})
	}
}

func TestDownloadCloudflaredBinaryIfItDNE_FailuresKeepExistingBinary(t *testing.T) {
	cases := []struct {
		name    string
		serve   func(w http.ResponseWriter, asset []byte)
		wantErr string
	}{
		{
			name: "hash mismatch",
			serve: func(w http.ResponseWriter, _ []byte) {
				_, _ = w.Write([]byte("tampered cloudflared asset"))
			},
			wantErr: "hash mismatch",
		},
		{
			name: "truncated body",
			serve: func(w http.ResponseWriter, asset []byte) {
				w.Header().Set("Content-Length", strconv.Itoa(len(asset)+1024))
				_, _ = w.Write(asset[:len(asset)/2])
			},
			wantErr: "error saving downloaded file",
		},
		{
			name: "non-200 status",
			serve: func(w http.ResponseWriter, _ []byte) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			wantErr: "unexpected status code: 500",
		},
	}
	for _, platform := range cloudflaredTestPlatforms {
		for _, tc := range cases {
			t.Run(platform.goos+"-"+platform.goarch+"/"+tc.name, func(t *testing.T) {
				env := newCloudflaredTestEnv(t, platform.goos, platform.goarch, tc.serve)
				existing := []byte("existing cloudflared binary")
				writeExistingCloudflaredBinary(t, env.fs, env.binaryPath, existing)

				err := env.cl.DownloadCloudflaredBinaryIfItDNE()
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)

				got, readErr := afero.ReadFile(env.fs, env.binaryPath)
				require.NoError(t, readErr)
				assert.Equal(t, string(existing), string(got), "the existing binary must be kept on failure")
				assert.Equal(t, int32(1), atomic.LoadInt32(env.requests))
				assertOnlyBinaryInstalled(t, env.fs, env.binaryPath)
			})
		}
	}
}

// TestCloudflaredPlatform_UnsupportedOSBehaviorUnchanged pins the historical
// behavior for unsupported operating systems: an error when no binary exists
// and a no-op when one does.
func TestCloudflaredPlatform_UnsupportedOSBehaviorUnchanged(t *testing.T) {
	memfs := afero.NewMemMapFs()
	fsStore := NewBasicStore().WithFileSystem(memfs)
	t.Setenv("HOME", t.TempDir())
	binaryPath, err := fsStore.GetBrevCloudflaredBinaryPath()
	require.NoError(t, err)

	prevGOOS, prevGOARCH := cloudflaredGOOS, cloudflaredGOARCH
	cloudflaredGOOS, cloudflaredGOARCH = "windows", "amd64"
	t.Cleanup(func() { cloudflaredGOOS, cloudflaredGOARCH = prevGOOS, prevGOARCH })

	cl := NewCloudflare(fsStore)

	err = cl.DownloadCloudflaredBinaryIfItDNE()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported OS windows for downloading Cloudflared binary")

	writeExistingCloudflaredBinary(t, memfs, binaryPath, []byte("existing cloudflared binary"))
	assert.NoError(t, cl.DownloadCloudflaredBinaryIfItDNE())
}
