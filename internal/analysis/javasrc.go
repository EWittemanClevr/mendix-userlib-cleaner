package analysis

import (
	"regexp"
	"sort"
	"strings"
)

// JavaRefs: what one .java file refers to. ByName: class names that only appear inside
// a string literal (Class.forName, driver names in config).
type JavaRefs struct {
	Types    []string `json:"types"`
	Packages []string `json:"packages"`
	ByName   []string `json:"byName"`
}

var (
	javaComments    = regexp.MustCompile(`/\*[\s\S]*?\*/|//[^\n]*`)
	javaStrip       = regexp.MustCompile(`/\*[\s\S]*?\*/|//[^\n]*|"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'`)
	javaByName      = regexp.MustCompile(`"((?:[a-z_][a-z0-9_]*\.){2,}[A-Z][A-Za-z0-9_$]*)"`)
	javaImport      = regexp.MustCompile(`(?m)^\s*import\s+(static\s+)?([\w.]+?)(\.\*)?\s*;`)
	javaPkgOrImport = regexp.MustCompile(`(?m)^\s*(package|import)\s[^;]*;`)
	javaQualified   = regexp.MustCompile(`(?:[a-z_][a-z0-9_]*\.)+[A-Z][A-Za-z0-9_]*`)
)

// ParseJavaSource: port of parseJavaSource in jars.js.
func ParseJavaSource(src string) JavaRefs {
	byName := map[string]bool{}
	for _, m := range javaByName.FindAllStringSubmatch(javaComments.ReplaceAllString(src, " "), -1) {
		n := m[1]
		if i := strings.Index(n, "$"); i >= 0 {
			n = n[:i]
		}
		byName[n] = true
	}
	code := javaStrip.ReplaceAllString(src, " ")
	types := map[string]bool{}
	packages := map[string]bool{}
	for _, m := range javaImport.FindAllStringSubmatch(code, -1) {
		isStatic, name, star := m[1] != "", m[2], m[3] != ""
		switch {
		case isStatic && star:
			types[name] = true
		case isStatic:
			// import static a.b.C.member;
			if i := strings.LastIndex(name, "."); i >= 0 {
				types[name[:i]] = true
			} else {
				types[""] = true
			}
		case star:
			packages[name] = true
		default:
			types[name] = true
		}
	}
	body := javaPkgOrImport.ReplaceAllString(code, " ")
	// JS uses a lookbehind (?<![\w.]); RE2 has none, so check the preceding byte instead.
	for _, loc := range javaQualified.FindAllStringIndex(body, -1) {
		if loc[0] > 0 && (isWordChar(body[loc[0]-1]) || body[loc[0]-1] == '.') {
			continue
		}
		types[body[loc[0]:loc[1]]] = true
	}
	for t := range types {
		delete(byName, t)
	}
	keep := func(m map[string]bool) []string {
		out := []string{}
		for k := range m {
			if !isPlatform(k) {
				out = append(out, k)
			}
		}
		sort.Strings(out)
		return out
	}
	return JavaRefs{Types: keep(types), Packages: keep(packages), ByName: keep(byName)}
}
