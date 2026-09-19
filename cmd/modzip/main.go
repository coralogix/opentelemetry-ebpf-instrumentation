// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

/*
modzip produces the Go module proxy assets for an OBI release from the current
(fully generated) working tree.

OBI generates its bpf2go and Java agent artifacts at build time and does not
commit them, so the module as fetched directly from VCS does not compile. The
release pipeline generates those artifacts into the working tree (via
"make release-source", which runs docker-generate and java-docker-build) and
then this tool packages a proper Go module zip from that generated tree. The
zip, together with the .mod and .info files, is published as a release asset and
served to the Go toolchain through a "mod"-type vanity redirector.

Given a version, it writes three files into the output directory (default ./dist):

  - obi-<version>.module.zip  built with golang.org/x/mod/zip.CreateFromDir for
    module.Version{Path: "go.opentelemetry.io/obi", Version: <version>}. This
    automatically excludes nested module directories (those with their own
    go.mod) and any vendor directory, matching what the Go module proxy serves.
  - obi-<version>.module.mod  a copy of the root go.mod.
  - obi-<version>.module.info  JSON {"Version":"<version>","Time":"<RFC3339 UTC>"}
    where Time is the committer time of the resolved revision.

Usage:

	go run ./cmd/modzip --version v1.2.3 [--source-dir .] [--dist-dir ./dist]
*/
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/mod/module"
	modzip "golang.org/x/mod/zip"
)

const modulePath = "go.opentelemetry.io/obi"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "modzip: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		version   string
		sourceDir string
		distDir   string
	)
	flag.StringVar(&version, "version", "", "module version to package (e.g. v1.2.3); required")
	flag.StringVar(&sourceDir, "source-dir", ".", "root of the fully generated module working tree")
	flag.StringVar(&distDir, "dist-dir", "dist", "output directory for the module assets")
	flag.Parse()

	if version == "" {
		return fmt.Errorf("--version is required")
	}
	if err := module.Check(modulePath, version); err != nil {
		return fmt.Errorf("invalid module version %q: %w", version, err)
	}

	absSource, err := filepath.Abs(sourceDir)
	if err != nil {
		return fmt.Errorf("resolving source dir: %w", err)
	}

	goModPath := filepath.Join(absSource, "go.mod")
	if _, err := os.Stat(goModPath); err != nil {
		return fmt.Errorf("root go.mod not found at %s: %w", goModPath, err)
	}

	if err := os.MkdirAll(distDir, 0o755); err != nil {
		return fmt.Errorf("creating dist dir: %w", err)
	}

	base := filepath.Join(distDir, fmt.Sprintf("obi-%s.module", version))
	zipPath := base + ".zip"
	modOut := base + ".mod"
	infoOut := base + ".info"

	mv := module.Version{Path: modulePath, Version: version}

	// Stage a clean tree to zip: the committed files at HEAD (via git archive)
	// plus the build-time generated artifacts that are not committed (bpf2go
	// outputs and the embedded Java agent JAR). This mirrors what
	// scripts/release-source.sh assembles and, crucially, keeps build-output
	// directories like dist/, bin/, and testoutput/ out of the published module
	// zip (CreateFromDir would otherwise include everything under the working
	// tree that is not a nested module or vendor dir).
	stageRoot, err := os.MkdirTemp("", "obi-modzip-stage-")
	if err != nil {
		return fmt.Errorf("creating staging dir: %w", err)
	}
	defer os.RemoveAll(stageRoot)

	if err := stageTree(absSource, stageRoot); err != nil {
		return fmt.Errorf("staging module tree: %w", err)
	}

	if err := writeZip(zipPath, mv, stageRoot); err != nil {
		return fmt.Errorf("creating module zip: %w", err)
	}

	if err := copyFile(goModPath, modOut); err != nil {
		return fmt.Errorf("copying go.mod: %w", err)
	}

	commitTime, err := revisionTime(absSource)
	if err != nil {
		return fmt.Errorf("resolving revision time: %w", err)
	}
	if err := writeInfo(infoOut, version, commitTime); err != nil {
		return fmt.Errorf("writing info: %w", err)
	}

	fmt.Printf("wrote %s\n", zipPath)
	fmt.Printf("wrote %s\n", modOut)
	fmt.Printf("wrote %s\n", infoOut)
	return nil
}

// generatedExts/Suffixes identify the build-time bpf2go outputs that are not
// committed but must be present in the module zip for it to compile. Mirrors the
// patterns in scripts/release-source.sh.
var generatedBPFSuffixes = []string{
	"_bpfel.go", "_bpfeb.go",
	"_bpfel.o", "_bpfeb.o",
	"_bpfel.go.d", "_bpfeb.go.d",
}

// javaAgentEmbedPath is the go:embed'ed Java agent JAR relative to the module
// root; it must be the real build output (not the committed placeholder) at zip
// time. Kept in sync with scripts/release-source.sh.
const javaAgentEmbedPath = "pkg/internal/java/embedded/obi-java-agent.jar"

// stageTree assembles, under stageRoot, the committed tree at HEAD plus the
// generated artifacts copied from the working tree, so the resulting zip
// contains exactly source + generated artifacts (and never build-output dirs
// such as dist/, bin/, testoutput/).
func stageTree(sourceDir, stageRoot string) error {
	// 1. Export the committed tree at HEAD: `git archive HEAD | tar -x`.
	archive := exec.Command("git", "-C", sourceDir, "archive", "--format=tar", "HEAD")
	stdout, err := archive.StdoutPipe()
	if err != nil {
		return err
	}
	untar := exec.Command("tar", "-x", "-C", stageRoot)
	untar.Stdin = stdout
	untar.Stderr = os.Stderr
	if err := archive.Start(); err != nil {
		return fmt.Errorf("git archive: %w", err)
	}
	if err := untar.Start(); err != nil {
		return fmt.Errorf("tar extract: %w", err)
	}
	if err := untar.Wait(); err != nil {
		return fmt.Errorf("tar extract: %w", err)
	}
	if err := archive.Wait(); err != nil {
		return fmt.Errorf("git archive: %w", err)
	}

	// 2. Copy the generated bpf2go artifacts from the working tree.
	pkgDir := filepath.Join(sourceDir, "pkg")
	generatedCount := 0
	walkErr := filepath.WalkDir(pkgDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !hasGeneratedBPFSuffix(d.Name()) {
			return nil
		}
		rel, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}
		dst := filepath.Join(stageRoot, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := copyFile(path, dst); err != nil {
			return err
		}
		generatedCount++
		return nil
	})
	if walkErr != nil {
		return fmt.Errorf("collecting generated bpf2go artifacts: %w", walkErr)
	}
	if generatedCount == 0 {
		return fmt.Errorf("no generated bpf2go artifacts found under %s; run 'make docker-generate' first", pkgDir)
	}

	// 3. Ensure the real embedded Java agent JAR is staged (git archive may
	//    carry the committed placeholder; the working-tree copy is the build
	//    output and must win).
	jarSrc := filepath.Join(sourceDir, javaAgentEmbedPath)
	jarDst := filepath.Join(stageRoot, javaAgentEmbedPath)
	if err := os.MkdirAll(filepath.Dir(jarDst), 0o755); err != nil {
		return err
	}
	if err := copyFile(jarSrc, jarDst); err != nil {
		return fmt.Errorf("staging Java agent JAR: %w", err)
	}

	return nil
}

func hasGeneratedBPFSuffix(name string) bool {
	for _, s := range generatedBPFSuffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

func writeZip(zipPath string, mv module.Version, sourceDir string) error {
	f, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer f.Close()

	// CreateFromDir walks sourceDir (the clean staging tree) and excludes nested
	// module directories (those containing their own go.mod) and vendor
	// directories, matching the contents the Go module proxy serves.
	if err := modzip.CreateFromDir(f, mv, sourceDir); err != nil {
		return err
	}
	return f.Close()
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

// revisionTime returns the committer time of HEAD in sourceDir, normalized to UTC.
func revisionTime(sourceDir string) (time.Time, error) {
	cmd := exec.Command("git", "-C", sourceDir, "log", "-1", "--format=%cI")
	out, err := cmd.Output()
	if err != nil {
		return time.Time{}, fmt.Errorf("git log: %w", err)
	}
	raw := strings.TrimSpace(string(out))
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing commit time %q: %w", raw, err)
	}
	return t.UTC(), nil
}

// revInfo mirrors the JSON layout the Go module proxy serves for a version's
// .info endpoint.
type revInfo struct {
	Version string
	Time    time.Time
}

func writeInfo(path, version string, commitTime time.Time) error {
	info := revInfo{
		Version: version,
		// time.Time marshals to RFC3339; force UTC so the "Z" suffix is used.
		Time: commitTime.UTC(),
	}
	data, err := json.Marshal(info)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}
