// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

/**
 * IOGO: Removed usage of godebug flags: x509usefallbackroots
 */

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	_ "unsafe" // for linkname
)

// systemRoots should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/breml/rootcerts
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname systemRoots
var (
	once             sync.Once
	systemRootsMu    sync.RWMutex
	systemRoots      *CertPool
	systemRootsErr   error
	fallbacksSet     bool
	useFallbackRoots bool
)

func systemRootsPool() *CertPool {
	once.Do(initSystemRoots)
	systemRootsMu.RLock()
	defer systemRootsMu.RUnlock()
	return systemRoots
}

func initSystemRoots() {
	systemRootsMu.Lock()
	defer systemRootsMu.Unlock()

	fallbackRoots := systemRoots
	systemRoots, systemRootsErr = loadSystemRoots()
	if systemRootsErr != nil {
		systemRoots = nil
	}

	if fallbackRoots == nil {
		return // no fallbacks to try
	}

	systemCertsAvail := systemRoots != nil && (systemRoots.len() > 0 || systemRoots.systemPool)

	if !useFallbackRoots && systemCertsAvail {
		return
	}

	systemRoots, systemRootsErr = fallbackRoots, nil
}

// SetFallbackRoots sets the roots to use during certificate verification, if no
// custom roots are specified and a platform verifier or a system certificate
// pool is not available (for instance in a container which does not have a root
// certificate bundle). SetFallbackRoots will panic if roots is nil.
//
// SetFallbackRoots may only be called once, if called multiple times it will
// panic.
//
// The fallback behavior can be forced on all platforms, even when there is a
// system certificate pool.
// IOGO: x509usefallbackroots godebug flag has no effect on this function
func SetFallbackRoots(roots *CertPool) {
	if roots == nil {
		panic("roots must be non-nil")
	}

	systemRootsMu.Lock()
	defer systemRootsMu.Unlock()

	if fallbacksSet {
		panic("SetFallbackRoots has already been called")
	}
	fallbacksSet = true

	// Handle case when initSystemRoots was not yet executed.
	// We handle that specially instead of calling loadSystemRoots, to avoid
	// spending excessive amount of cpu here, since the SetFallbackRoots in most cases
	// is going to be called at program startup.
	if systemRoots == nil && systemRootsErr == nil {
		systemRoots = roots
		useFallbackRoots = false
		return
	}

	once.Do(func() { panic("unreachable") }) // asserts that system roots were indeed loaded before.

	forceFallbackRoots := false
	systemCertsAvail := systemRoots != nil && (systemRoots.len() > 0 || systemRoots.systemPool)

	if !forceFallbackRoots && systemCertsAvail {
		return
	}

	systemRoots, systemRootsErr = roots, nil
}

const (
	// certFileEnv is the environment variable which identifies where to locate
	// the SSL certificate file. If set this overrides the system default.
	certFileEnv = "SSL_CERT_FILE"

	// certDirEnv is the environment variable which identifies which directory
	// to check for SSL certificate files. If set this overrides the system default.
	// See https://docs.openssl.org/4.0/man1/openssl-rehash/#environment.
	certDirEnv = "SSL_CERT_DIR"
)

func loadSystemRoots() (*CertPool, error) {
	certFilePath, certDirPath := os.Getenv(certFileEnv), os.Getenv(certDirEnv)

	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" || runtime.GOOS == "ios" {
		if certFilePath == "" && certDirPath == "" {
			return &CertPool{systemPool: true}, nil
		}
	}

	return loadOnDiskRoots(certFilePath, certDirPath)
}

func loadOnDiskRoots(certFilePath, certDirPath string) (*CertPool, error) {
	roots := NewCertPool()

	files := certFiles
	if certFilePath != "" {
		files = []string{certFilePath}
	}

	var firstErr error
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err == nil {
			roots.AppendCertsFromPEM(data)
			break
		}
		if firstErr == nil && !os.IsNotExist(err) {
			firstErr = err
		}
	}

	dirs := certDirectories
	if certDirPath != "" {
		// OpenSSL and BoringSSL both use ":" as the SSL_CERT_DIR separator on
		// Unix-like systems, and ";" on Windows.
		// See:
		//  * https://golang.org/issue/35325
		//  * https://docs.openssl.org/4.0/man1/openssl-rehash/#environment
		dirs = filepath.SplitList(certDirPath)
	}

	for _, directory := range dirs {
		fis, err := readUniqueDirectoryEntries(directory)
		if err != nil {
			if firstErr == nil && !os.IsNotExist(err) {
				firstErr = err
			}
			continue
		}
		for _, fi := range fis {
			data, err := os.ReadFile(filepath.Join(directory, fi.Name()))
			if err == nil {
				roots.AppendCertsFromPEM(data)
			}
		}
	}

	if roots.len() > 0 || firstErr == nil {
		return roots, nil
	}

	return nil, firstErr
}

// readUniqueDirectoryEntries is like os.ReadDir but omits
// symlinks that point within the directory.
func readUniqueDirectoryEntries(dir string) ([]fs.DirEntry, error) {
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	uniq := files[:0]
	for _, f := range files {
		if !isSameDirSymlink(f, dir) {
			uniq = append(uniq, f)
		}
	}
	return uniq, nil
}

// isSameDirSymlink reports whether f in dir is a symlink with a
// target not containing a slash.
func isSameDirSymlink(f fs.DirEntry, dir string) bool {
	if f.Type()&fs.ModeSymlink == 0 {
		return false
	}
	target, err := os.Readlink(filepath.Join(dir, f.Name()))
	return err == nil && !strings.ContainsRune(target, filepath.Separator)
}
