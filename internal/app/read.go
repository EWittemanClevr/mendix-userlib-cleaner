// Package app reads a Mendix app checkout from disk and moves jars out of (and back
// into) its userlib folder.
package app

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/EWittemanClevr/mendix-userlib-cleaner/internal/analysis"
	"go.mongodb.org/mongo-driver/v2/bson"
	_ "modernc.org/sqlite"
)

type App struct {
	Dir           string
	MprFile       string
	MendixVersion string
	Input         analysis.Input
	Sha256        map[string]string
}

// FindMpr returns the .mpr file name in dir, or "" when dir isn't a Mendix app.
func FindMpr(dir string) string {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if !e.IsDir() && strings.EqualFold(filepath.Ext(e.Name()), ".mpr") {
			return e.Name()
		}
	}
	return ""
}

// .NET stores GUIDs mixed-endian: first three groups byte-reversed, last two as-is.
func guidFromDotNetBytes(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	h := hex.EncodeToString(b)
	rev := func(s string) string {
		var out strings.Builder
		for i := len(s) - 2; i >= 0; i -= 2 {
			out.WriteString(s[i : i+2])
		}
		return out.String()
	}
	return fmt.Sprintf("%s-%s-%s-%s-%s", rev(h[0:8]), rev(h[8:12]), rev(h[12:16]), h[16:20], h[20:])
}

var requiredLibRe = regexp.MustCompile(`(?i)^userlib/(.+\.jar)\.([^/.]+)\.RequiredLib$`)
var jarRe = regexp.MustCompile(`(?i)^(userlib|vendorlib)/[^/]+\.jar$`)
var javaRe = regexp.MustCompile(`^javasource/[^/]+/.+\.java$`)

func walk(root, rel string) []string {
	var out []string
	_ = filepath.WalkDir(filepath.Join(root, rel), func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			r, _ := filepath.Rel(root, p)
			out = append(out, filepath.ToSlash(r))
		}
		return nil
	})
	sort.Strings(out)
	return out
}

func Read(dir string) (*App, error) {
	mpr := FindMpr(dir)
	if mpr == "" {
		return nil, fmt.Errorf("no .mpr file in %s", dir)
	}
	a := &App{Dir: dir, MprFile: mpr, Sha256: map[string]string{}}
	if err := readModel(a); err != nil {
		return nil, fmt.Errorf("reading %s: %w", mpr, err)
	}

	files := append(append(walk(dir, "userlib"), walk(dir, "vendorlib")...), walk(dir, "javasource")...)
	var jarPaths, javaPaths []string
	for _, p := range files {
		switch {
		case jarRe.MatchString(p):
			jarPaths = append(jarPaths, p)
		case javaRe.MatchString(p):
			// Generated entity proxies only reference the Mendix API; skip them.
			if !strings.HasPrefix(strings.SplitN(p, "/", 3)[2], "proxies/") {
				javaPaths = append(javaPaths, p)
			}
		case requiredLibRe.MatchString(p):
			m := requiredLibRe.FindStringSubmatch(p)
			a.Input.RequiredLibs = append(a.Input.RequiredLibs, analysis.RequiredLib{Jar: "userlib/" + m[1], Module: m[2], Marker: p})
		}
	}

	// Jars are the slow part (bytecode of every class): parse them in parallel.
	a.Input.Jars = make([]analysis.Jar, len(jarPaths))
	var wg sync.WaitGroup
	sem := make(chan struct{}, runtime.NumCPU())
	var mu sync.Mutex
	for i, p := range jarPaths {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			buf, err := os.ReadFile(filepath.Join(dir, p))
			info := analysis.JarInfo{Error: fmt.Sprint(err)}
			if err == nil {
				info = analysis.ParseJar(buf, p)
				sum := sha256.Sum256(buf)
				mu.Lock()
				a.Sha256[p] = hex.EncodeToString(sum[:])
				mu.Unlock()
			}
			a.Input.Jars[i] = analysis.Jar{Path: p, BlobSha: p, Info: info}
		}()
	}
	wg.Wait()
	for _, p := range javaPaths {
		src, err := os.ReadFile(filepath.Join(dir, p))
		if err == nil {
			a.Input.JavaFiles = append(a.Input.JavaFiles, analysis.JavaFile{Path: p, Refs: analysis.ParseJavaSource(string(src))})
		}
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "vendorlib", "vendorlib-sbom.json")); err == nil {
		var s analysis.Sbom
		if json.Unmarshal(raw, &s) == nil {
			a.Input.Sbom = &s
		}
	}
	return a, nil
}

// readModel: Studio Pro version, module names and module Java dependencies from the .mpr
// (SQLite) and its mprcontents/ unit files (BSON).
func readModel(a *App) error {
	abs, _ := filepath.Abs(filepath.Join(a.Dir, a.MprFile))
	// immutable=1: read without locks and without creating -wal/-shm files next to the model.
	dsn := (&url.URL{Scheme: "file", Path: "/" + filepath.ToSlash(abs)}).String() + "?mode=ro&immutable=1"
	if runtime.GOOS != "windows" {
		dsn = (&url.URL{Scheme: "file", Path: filepath.ToSlash(abs)}).String() + "?mode=ro&immutable=1"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	cols := map[string]bool{}
	if rows, err := db.Query(`SELECT * FROM _MetaData LIMIT 1`); err == nil {
		names, _ := rows.Columns()
		if rows.Next() {
			vals := make([]any, len(names))
			ptrs := make([]any, len(names))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			_ = rows.Scan(ptrs...)
			for i, n := range names {
				if (n == "_ProductVersion" || n == "ProductVersion") && vals[i] != nil && a.MendixVersion == "" {
					a.MendixVersion = fmt.Sprint(asString(vals[i]))
				}
			}
		}
		rows.Close()
	}
	if rows, err := db.Query(`PRAGMA table_info(Unit)`); err == nil {
		for rows.Next() {
			var cid int
			var name, typ string
			var notnull, pk int
			var dflt any
			if rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk) == nil {
				cols[name] = true
			}
		}
		rows.Close()
	}
	hasContents := cols["Contents"]
	q := `SELECT UnitID, ContainerID, ContainmentName FROM Unit WHERE ContainmentName IN ('Modules', 'ModuleSettings')`
	if hasContents {
		q = `SELECT UnitID, ContainerID, ContainmentName, Contents FROM Unit WHERE ContainmentName IN ('Modules', 'ModuleSettings')`
	}
	rows, err := db.Query(q)
	if err != nil {
		return err
	}
	type unit struct {
		id, container, kind string
		raw                 []byte
	}
	var units []unit
	for rows.Next() {
		var id, container []byte
		var kind string
		var contents []byte
		if hasContents {
			err = rows.Scan(&id, &container, &kind, &contents)
		} else {
			err = rows.Scan(&id, &container, &kind)
		}
		if err != nil {
			rows.Close()
			return err
		}
		units = append(units, unit{guidFromDotNetBytes(id), guidFromDotNetBytes(container), kind, contents})
	}
	rows.Close()

	read := func(u unit) []byte {
		if hasContents {
			return u.raw
		}
		b, _ := os.ReadFile(filepath.Join(a.Dir, "mprcontents", u.id[0:2], u.id[2:4], u.id+".mxunit"))
		return b
	}
	moduleByGuid := map[string]string{}
	for _, u := range units {
		if u.kind != "Modules" {
			continue
		}
		doc := bson.Raw(read(u))
		if doc.Validate() != nil || lookupString(doc, "$Type") != "Projects$ModuleImpl" {
			continue
		}
		name := lookupString(doc, "Name")
		moduleByGuid[u.id] = name
		a.Input.ModuleNames = append(a.Input.ModuleNames, name)
	}
	if len(a.Input.ModuleNames) == 0 {
		return fmt.Errorf("no modules found (unexpected .mpr format?)")
	}
	for _, u := range units {
		if u.kind != "ModuleSettings" {
			continue
		}
		doc := bson.Raw(read(u))
		if doc.Validate() != nil || lookupString(doc, "$Type") != "Projects$ModuleSettings" {
			continue
		}
		deps, err := doc.LookupErr("JarDependencies")
		if err != nil {
			continue
		}
		arr, ok := deps.ArrayOK()
		if !ok {
			continue
		}
		vals, _ := arr.Values()
		for _, v := range vals {
			d, ok := v.DocumentOK()
			if !ok || lookupString(d, "$Type") != "Projects$JarDependency" {
				continue
			}
			if inc, err := d.LookupErr("IsIncluded"); err == nil {
				if b, ok := inc.BooleanOK(); ok && !b {
					continue
				}
			}
			dep := analysis.JarDependency{Module: moduleByGuid[u.container], Group: lookupString(d, "GroupId"),
				Artifact: lookupString(d, "ArtifactId"), Version: lookupString(d, "Version")}
			if dep.Artifact != "" {
				a.Input.JarDependencies = append(a.Input.JarDependencies, dep)
			}
		}
	}
	return nil
}

func lookupString(doc bson.Raw, key string) string {
	v, err := doc.LookupErr(key)
	if err != nil {
		return ""
	}
	if s, ok := v.StringValueOK(); ok {
		return s
	}
	if i, ok := v.Int32OK(); ok {
		return strconv.Itoa(int(i))
	}
	return ""
}

func asString(v any) string {
	if b, ok := v.([]byte); ok {
		return string(b)
	}
	return fmt.Sprint(v)
}
