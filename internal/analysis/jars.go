package analysis

// Reading jars: Maven coordinates, the classes a jar provides, the packages its bytecode
// refers to, and its ServiceLoader registrations.

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"io"
	"regexp"
	"sort"
	"strings"
)

// JarInfo is what one jar file tells us about itself.
type JarInfo struct {
	Group       string   `json:"group,omitempty"`
	Artifact    string   `json:"artifact,omitempty"`
	Version     string   `json:"version,omitempty"`
	CoordSource string   `json:"coordSource,omitempty"`
	Classes     []string `json:"classes"`
	RefPackages []string `json:"refPackages"`
	Services    []string `json:"services"`
	Error       string   `json:"error,omitempty"`
}

var javaxLibraries = []string{"mail", "activation", "annotation", "xml.bind", "ws.rs", "json", "inject", "validation", "servlet"}

// isPlatform: JDK packages are never provided by userlib/vendorlib. (Not com.mendix:
// Mendix's own module jars use that namespace too.) javax.mail & co. are libraries.
func isPlatform(n string) bool {
	for _, p := range []string{"java", "jdk", "sun"} {
		if n == p || strings.HasPrefix(n, p+".") {
			return true
		}
	}
	if rest, ok := strings.CutPrefix(n, "javax."); ok && rest != "" {
		for _, lib := range javaxLibraries {
			if strings.HasPrefix(rest, lib) {
				return false
			}
		}
		return isWordChar(rest[0])
	}
	return false
}

func isWordChar(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// A fully qualified class name in a string ("org.postgresql.Driver"): loaded by name.
var fqnString = regexp.MustCompile(`^(?:[a-z_][a-z0-9_]*\.){2,}[A-Z][A-Za-z0-9_$]*$`)
var descriptorType = regexp.MustCompile(`L([A-Za-z_$][\w$]*(?:/[\w$]+)+);`)
var arrayElement = regexp.MustCompile(`L([^;]+);`)

func PackageOf(fqn string) string {
	if i := strings.LastIndex(fqn, "."); i > 0 {
		return fqn[:i]
	}
	return ""
}

// ClassFileRefs returns the type names a class file refers to (internal names, with
// slashes): CONSTANT_Class entries, `Lpkg/Name;` in descriptors and signatures, and
// string constants that are a class name (Class.forName-style loading).
func ClassFileRefs(buf []byte) []string {
	if len(buf) < 10 || binary.BigEndian.Uint32(buf) != 0xCAFEBABE {
		return nil
	}
	count := int(binary.BigEndian.Uint16(buf[8:]))
	utf8 := map[int]string{}
	var utf8Order []int
	var classIdx []int
	p := 10
	for i := 1; i < count; i++ {
		if p >= len(buf) {
			return nil
		}
		tag := buf[p]
		p++
		need := func(n int) bool { return p+n <= len(buf) }
		switch tag {
		case 1:
			if !need(2) {
				return nil
			}
			l := int(binary.BigEndian.Uint16(buf[p:]))
			if !need(2 + l) {
				return nil
			}
			utf8[i] = latin1(buf[p+2 : p+2+l])
			utf8Order = append(utf8Order, i)
			p += 2 + l
		case 7:
			if !need(2) {
				return nil
			}
			classIdx = append(classIdx, int(binary.BigEndian.Uint16(buf[p:])))
			p += 2
		case 8, 16, 19, 20:
			p += 2
		case 15:
			p += 3
		case 3, 4, 9, 10, 11, 12, 17, 18:
			p += 4
		case 5, 6:
			p += 8
			i++
		default:
			return nil // unknown tag: give up on this class rather than misread it
		}
		if p > len(buf) {
			return nil
		}
	}
	out := newOrderedSet()
	for _, idx := range classIdx {
		n, ok := utf8[idx]
		if !ok || n == "" {
			continue
		}
		if strings.HasPrefix(n, "[") {
			if m := arrayElement.FindStringSubmatch(n); m != nil {
				out.add(m[1])
			}
		} else {
			out.add(n)
		}
	}
	for _, idx := range utf8Order {
		s := utf8[idx]
		if fqnString.MatchString(s) {
			out.add(strings.ReplaceAll(s, ".", "/"))
			continue
		}
		if !strings.Contains(s, ";") {
			continue
		}
		for _, m := range descriptorType.FindAllStringSubmatch(s, -1) {
			out.add(m[1])
		}
	}
	return out.items
}

// The JS side decodes class file strings as latin1; do the same so both see the same names.
func latin1(b []byte) string {
	r := make([]rune, len(b))
	for i, c := range b {
		r[i] = rune(c)
	}
	return string(r)
}

var versionsPrefix = regexp.MustCompile(`^META-INF/versions/\d+/`)

func outerClass(entry string) string {
	s := versionsPrefix.ReplaceAllString(entry, "")
	s = strings.TrimSuffix(s, ".class")
	if i := strings.Index(s, "$"); i >= 0 {
		s = s[:i]
	}
	return strings.ReplaceAll(s, "/", ".")
}

var pomPropsPath = regexp.MustCompile(`^META-INF/maven/[^/]+/[^/]+/pom\.properties$`)
var servicesPath = regexp.MustCompile(`^META-INF/services/[^/]+$`)
var hashComment = regexp.MustCompile(`(?m)#.*$`)
var infoClass = regexp.MustCompile(`(^|/)(module-info|package-info)\.class$`)
var fileNameCoords = regexp.MustCompile(`^(.*?)-(\d[\w.+-]*)$`)

func prop(txt, key, sep string) string {
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(key) + `\s*` + sep + `\s*(.+?)\s*$`)
	if m := re.FindStringSubmatch(txt); m != nil {
		return m[1]
	}
	return ""
}

func baseName(fileName string) string {
	b := fileName[strings.LastIndex(fileName, "/")+1:]
	if strings.HasSuffix(strings.ToLower(b), ".jar") {
		b = b[:len(b)-4]
	}
	return b
}

// CoordsFromFileName: "guava-33.5.0-jre.jar" → ("guava", "33.5.0-jre").
func CoordsFromFileName(fileName string) (artifact, version string) {
	b := baseName(fileName)
	if m := fileNameCoords.FindStringSubmatch(b); m != nil {
		return m[1], m[2]
	}
	return b, ""
}

func readEntry(f *zip.File) []byte {
	rc, err := f.Open()
	if err != nil {
		return nil
	}
	defer rc.Close()
	b, _ := io.ReadAll(rc)
	return b
}

type coords struct{ group, artifact, version string }

func coordsFromPomProps(files []*zip.File, base string) *coords {
	var parsed []coords
	for _, f := range files {
		if !pomPropsPath.MatchString(f.Name) {
			continue
		}
		txt := string(readEntry(f))
		c := coords{prop(txt, "groupId", "="), prop(txt, "artifactId", "="), prop(txt, "version", "=")}
		if c.group != "" && c.artifact != "" && c.version != "" {
			parsed = append(parsed, c)
		}
	}
	if len(parsed) == 0 {
		return nil
	}
	// Shaded jars carry the pom.properties of everything they bundle; prefer the one
	// that matches the file name.
	for _, c := range parsed {
		if strings.HasPrefix(base, c.artifact+"-"+c.version) {
			return &c
		}
	}
	for _, c := range parsed {
		if strings.HasPrefix(base, c.artifact) {
			return &c
		}
	}
	if len(parsed) == 1 {
		return &parsed[0]
	}
	return nil
}

// ParseJar reads coordinates, provided classes, bytecode package references and
// ServiceLoader registrations from one jar.
func ParseJar(buf []byte, fileName string) JarInfo {
	zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	if err != nil {
		return JarInfo{Error: err.Error()}
	}
	base := baseName(fileName)
	info := JarInfo{}
	if c := coordsFromPomProps(zr.File, base); c != nil {
		info.Group, info.Artifact, info.Version, info.CoordSource = c.group, c.artifact, c.version, "pom"
	} else {
		mf := ""
		for _, f := range zr.File {
			if f.Name == "META-INF/MANIFEST.MF" {
				mf = string(readEntry(f))
			}
		}
		info.Artifact, info.Version = CoordsFromFileName(fileName)
		if info.Version == "" {
			info.Version = prop(mf, "Bundle-Version", ":")
		}
		if info.Version == "" {
			info.Version = prop(mf, "Implementation-Version", ":")
		}
		info.CoordSource = "filename"
	}
	classes := map[string]bool{}
	own := map[string]bool{}
	refs := map[string]bool{}
	services := map[string]bool{}
	for _, f := range zr.File {
		n := f.Name
		if servicesPath.MatchString(n) {
			if strings.TrimSpace(hashComment.ReplaceAllString(string(readEntry(f)), "")) != "" {
				services[n[strings.LastIndex(n, "/")+1:]] = true
			}
			continue
		}
		if !strings.HasSuffix(n, ".class") || infoClass.MatchString(n) {
			continue
		}
		fqn := outerClass(n)
		classes[fqn] = true
		own[PackageOf(fqn)] = true
		for _, r := range ClassFileRefs(readEntry(f)) {
			if i := strings.Index(r, "$"); i >= 0 {
				r = r[:i]
			}
			pkg := PackageOf(strings.ReplaceAll(r, "/", "."))
			if pkg != "" && !isPlatform(pkg) {
				refs[pkg] = true
			}
		}
	}
	for pkg := range own {
		delete(refs, pkg)
	}
	info.Classes, info.RefPackages, info.Services = sortedKeys(classes), sortedKeys(refs), sortedKeys(services)
	return info
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var bcJdkSuffix = regexp.MustCompile(`-jdk\d+(?:to\d+|on)?$`)

// LibraryKey: Bouncy Castle ships the same classes as bcprov-jdk15on, -jdk18on,
// -jdk15to18 …: those are one library for duplicate detection.
func LibraryKey(group, artifact string) string {
	a := bcJdkSuffix.ReplaceAllString(strings.ToLower(artifact), "")
	g := strings.ToLower(group)
	if g == "" {
		g = "?"
	}
	return g + ":" + a
}

// orderedSet keeps insertion order, like a JS Set.
type orderedSet struct {
	seen  map[string]bool
	items []string
}

func newOrderedSet() *orderedSet { return &orderedSet{seen: map[string]bool{}} }

func (s *orderedSet) add(v string) {
	if !s.seen[v] {
		s.seen[v] = true
		s.items = append(s.items, v)
	}
}
