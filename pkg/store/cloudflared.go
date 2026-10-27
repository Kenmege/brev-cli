package store

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/brevdev/brev-cli/pkg/collections"
	"github.com/brevdev/brev-cli/pkg/errors"
)

type CloudflaredStore interface {
	GetBrevCloudflaredBinaryPath() (string, error)
	FileExists(string) (bool, error)
	DownloadBinary(string, string) error
	Chmod(string, fs.FileMode) error
	MkdirAll(string, fs.FileMode) error
	Create(string) (io.WriteCloser, error)
	Open(string) (io.ReadCloser, error)
	Remove(string) error
	Rename(string, string) error
}

type Cloudflared struct {
	store CloudflaredStore
}

func NewCloudflare(store CloudflaredStore) Cloudflared {
	return Cloudflared{
		store: store,
	}
}

var CloudflaredVersion = "2026.10.4"

// cloudflaredPin pins one release asset of CloudflaredVersion. ArchiveSha256
// is the sha256 of the asset exactly as downloaded from the release (for
// darwin that is the .tgz archive). ExecutableSha256 is the sha256 of the
// executable installed at the binary path (for darwin, the single
// "cloudflared" file extracted from the archive; for linux, the asset
// itself).
type cloudflaredPin struct {
	AssetName        string
	ArchiveSha256    string
	ExecutableSha256 string
}

var defaultCloudflaredPins = map[string]cloudflaredPin{
	"darwin-amd64": {
		AssetName:        "cloudflared-darwin-amd64.tgz",
		ArchiveSha256:    "f11fbef4207d715892331917dafd437f032cf4b7137ed64dea3008338c1c613d",
		ExecutableSha256: "fdec0f9a1c726f4c10283fc0cd70e602d510c72887b737270433c81a08c883a9",
	},
	"darwin-arm64": {
		AssetName:        "cloudflared-darwin-arm64.tgz",
		ArchiveSha256:    "68b6bc4080ac1330234db2a9002d07f98b000537a1bd531a687b660d4160fa7f",
		ExecutableSha256: "49e7963072b2ca83fb44c09f4d4a7cda52d390c0c9c6f55bac83454a5bc43910",
	},
	"linux-amd64": {
		AssetName:        "cloudflared-linux-amd64",
		ArchiveSha256:    "ae5e8add7884b0531d66bbca4570d1de491ff6da51e4ebe7eb160cdf241d9e42",
		ExecutableSha256: "ae5e8add7884b0531d66bbca4570d1de491ff6da51e4ebe7eb160cdf241d9e42",
	},
	"linux-arm64": {
		AssetName:        "cloudflared-linux-arm64",
		ArchiveSha256:    "2b7203b4fb0ba28a0c1e12f8855ce2c25f76d266a8d5edafac5540b6812acff6",
		ExecutableSha256: "2b7203b4fb0ba28a0c1e12f8855ce2c25f76d266a8d5edafac5540b6812acff6",
	},
}

// Package-level indirections so tests can point downloads at a local
// httptest server and install synthetic pins. The defaults preserve
// production behavior.
var (
	cloudflaredBaseURL = "https://github.com/cloudflare/cloudflared/releases/download"
	cloudflaredGOOS    = runtime.GOOS
	cloudflaredGOARCH  = runtime.GOARCH
	cloudflaredPins    = defaultCloudflaredPins
)

// DownloadCloudflaredBinaryIfItDNE installs the pinned cloudflared version.
// An existing binary is only considered current when its sha256 equals the
// pinned executable hash; anything else (missing, outdated or replaced by a
// different version) triggers a fresh download.
func (c Cloudflared) DownloadCloudflaredBinaryIfItDNE() error {
	binaryPath, err := c.store.GetBrevCloudflaredBinaryPath()
	if err != nil {
		return errors.WrapAndTrace(err)
	}
	binaryExists, err := c.store.FileExists(binaryPath)
	if err != nil {
		return errors.WrapAndTrace(err)
	}
	pin, pinErr := currentCloudflaredPin()
	if pinErr != nil {
		// Unsupported platform: keep the historical behavior of leaving an
		// existing binary alone.
		if binaryExists {
			return nil
		}
		return errors.WrapAndTrace(pinErr)
	}
	if binaryExists {
		current, err := c.fileSha256(binaryPath)
		if err != nil {
			return errors.WrapAndTrace(err)
		}
		if current == pin.ExecutableSha256 {
			return nil
		}
	}
	binaryURL, err := getCloudflaredBinaryDownloadURL()
	if err != nil {
		return errors.WrapAndTrace(err)
	}
	err = c.DownloadBinary(context.TODO(), binaryPath, binaryURL)
	if err != nil {
		return errors.WrapAndTrace(err)
	}
	return nil
}

// DownloadBinary downloads the cloudflared asset from binaryURL, verifies it
// against the pinned sha256 hashes and installs it at binaryPath. The
// download is staged in temp files next to binaryPath and renamed into place
// only after verification, so a failed, interrupted or tampered download
// never corrupts an existing binary.
func (c Cloudflared) DownloadBinary(ctx context.Context, binaryPath, binaryURL string) error {
	pin, err := currentCloudflaredPin()
	if err != nil {
		return errors.WrapAndTrace(err)
	}
	resp, err := collections.GetRequestWithContext(ctx, binaryURL)
	if err != nil {
		return errors.WrapAndTrace(err)
	}
	defer resp.Body.Close() //nolint:errcheck // defer

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	err = c.store.MkdirAll(filepath.Dir(binaryPath), 0o755)
	if err != nil {
		return errors.WrapAndTrace(err)
	}

	return c.stageAndInstall(resp.Body, binaryPath, pin)
}

// stageAndInstall writes the download to a temp file next to binaryPath,
// verifies it against the pinned hashes and renames it onto binaryPath. On
// any failure the staging files are removed and an existing binary is kept.
func (c Cloudflared) stageAndInstall(body io.Reader, binaryPath string, pin cloudflaredPin) error {
	downloadPath := binaryPath + ".download"
	installPath := binaryPath + ".install"
	defer func() {
		_ = c.store.Remove(downloadPath) //nolint:errcheck // best effort cleanup
		_ = c.store.Remove(installPath)  //nolint:errcheck // best effort cleanup
	}()

	isArchive := strings.HasSuffix(pin.AssetName, ".tgz")
	wantDownloadSha := pin.ExecutableSha256
	if isArchive {
		wantDownloadSha = pin.ArchiveSha256
	}
	if err := c.writeVerified(body, downloadPath, pin.AssetName, wantDownloadSha); err != nil {
		return err
	}

	stagedPath := downloadPath
	if isArchive {
		if err := c.extractVerified(downloadPath, installPath, pin); err != nil {
			return err
		}
		stagedPath = installPath
	}

	if err := c.store.Chmod(stagedPath, 0o755); err != nil {
		return errors.WrapAndTrace(err)
	}
	if err := c.store.Rename(stagedPath, binaryPath); err != nil {
		return errors.WrapAndTrace(err)
	}
	return nil
}

// writeVerified streams body to path and fails unless the written file's
// sha256 matches wantSha.
func (c Cloudflared) writeVerified(body io.Reader, path, assetName, wantSha string) error {
	out, err := c.store.Create(path)
	if err != nil {
		return errors.WrapAndTrace(err)
	}
	_, err = io.Copy(out, body)
	if err != nil {
		_ = out.Close() //nolint:errcheck // best effort
		return fmt.Errorf("error saving downloaded file: %v", err)
	}
	if err := out.Close(); err != nil {
		return errors.WrapAndTrace(err)
	}
	gotSha, err := c.fileSha256(path)
	if err != nil {
		return errors.WrapAndTrace(err)
	}
	if gotSha != wantSha {
		return hashMismatchError(assetName, wantSha, gotSha)
	}
	return nil
}

// extractVerified extracts the single cloudflared executable from the
// verified .tgz archive at archivePath into execPath and fails unless its
// sha256 matches the pinned executable hash.
func (c Cloudflared) extractVerified(archivePath, execPath string, pin cloudflaredPin) error {
	archive, err := c.store.Open(archivePath)
	if err != nil {
		return errors.WrapAndTrace(err)
	}
	defer archive.Close() //nolint:errcheck // defer

	gzReader, err := gzip.NewReader(archive)
	if err != nil {
		return errors.WrapAndTrace(err)
	}
	tarReader := tar.NewReader(gzReader)
	if _, err = tarReader.Next(); err != nil {
		return errors.WrapAndTrace(fmt.Errorf("cloudflared archive %s has no executable entry: %w", pin.AssetName, err))
	}

	out, err := c.store.Create(execPath)
	if err != nil {
		return errors.WrapAndTrace(err)
	}
	hasher := sha256.New()
	if _, err = io.Copy(out, io.TeeReader(tarReader, hasher)); err != nil {
		_ = out.Close() //nolint:errcheck // best effort
		return errors.WrapAndTrace(err)
	}
	if err := out.Close(); err != nil {
		return errors.WrapAndTrace(err)
	}

	gotSha := hex.EncodeToString(hasher.Sum(nil))
	if gotSha != pin.ExecutableSha256 {
		return hashMismatchError(pin.AssetName, pin.ExecutableSha256, gotSha)
	}
	return nil
}

func (c Cloudflared) fileSha256(path string) (string, error) {
	file, err := c.store.Open(path)
	if err != nil {
		return "", errors.WrapAndTrace(err)
	}
	defer file.Close() //nolint:errcheck // defer

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", errors.WrapAndTrace(err)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func hashMismatchError(assetName, wantSha, gotSha string) error {
	return fmt.Errorf(
		"cloudflared %s asset %s hash mismatch: expected sha256 %s, got %s",
		CloudflaredVersion, assetName, wantSha, gotSha,
	)
}

// cloudflaredPlatformKey maps the current platform to a pin key, preserving
// the historical asset mapping (non-arm64 linux and darwin use the amd64
// asset).
func cloudflaredPlatformKey() (string, error) {
	switch cloudflaredGOOS {
	case "linux":
		if cloudflaredGOARCH == "arm64" {
			return "linux-arm64", nil
		}
		return "linux-amd64", nil
	case "darwin":
		if cloudflaredGOARCH == "arm64" {
			return "darwin-arm64", nil
		}
		return "darwin-amd64", nil
	default:
		return "", fmt.Errorf("unsupported OS %s for downloading Cloudflared binary", cloudflaredGOOS)
	}
}

func currentCloudflaredPin() (cloudflaredPin, error) {
	key, err := cloudflaredPlatformKey()
	if err != nil {
		return cloudflaredPin{}, err
	}
	pin, ok := cloudflaredPins[key]
	if !ok {
		return cloudflaredPin{}, fmt.Errorf("no pinned cloudflared %s asset for %s", CloudflaredVersion, key)
	}
	return pin, nil
}

func getCloudflaredBinaryDownloadURL() (string, error) {
	pin, err := currentCloudflaredPin()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/%s/%s", cloudflaredBaseURL, CloudflaredVersion, pin.AssetName), nil
}
