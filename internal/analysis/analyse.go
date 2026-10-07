package analysis

// Which jars an app actually uses. Usage per jar, strongest first: code (Java code references a class, also by name in a string), dependency
// (reachable from a code-used jar via bytecode package references or SBOM edges),
// declared (a module declares it, or it's reachable from one), runtime (registers a
// ServiceLoader provider for a JDK interface or a library in use), unused. Two copies of
// one library: the newest is effective, the others superseded/duplicate.

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
)

type Jar struct {
	Path    string
	BlobSha string
	Info    JarInfo
}

type JavaFile struct {
	Path string
	Refs JavaRefs
}

type RequiredLib struct {
	Jar    string `json:"jar"`
	Module string `json:"module"`
	Marker string `json:"marker"`
}

type JarDependency struct {
	Module   string `json:"module"`
	Group    string `json:"group"`
	Artifact string `json:"artifact"`
	Version  string `json:"version"`
}

// Sbom is the part of vendorlib/vendorlib-sbom.json (CycloneDX) we use.
type Sbom struct {
	Components []struct {
		Purl    string `json:"purl"`
		Group   string `json:"group"`
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"components"`
	Dependencies []struct {
		Ref       string   `json:"ref"`
		DependsOn []string `json:"dependsOn"`
	} `json:"dependencies"`
}

type Input struct {
	Jars            []Jar
	JavaFiles       []JavaFile
	RequiredLibs    []RequiredLib
	JarDependencies []JarDependency
	Sbom            *Sbom
	ModuleNames     []string
}

type User struct {
	Module string `json:"module"`
	File   string `json:"file"`
	Action string `json:"action,omitempty"`
	ByName bool   `json:"byName,omitempty"`
}

type Overlap struct {
	Path    string `json:"path"`
	Classes int    `json:"classes"`
}

type Lib struct {
	Path         string    `json:"path"`
	Dir          string    `json:"dir"`
	File         string    `json:"file"`
	Group        string    `json:"group"`
	Artifact     string    `json:"artifact"`
	Version      string    `json:"version"`
	CoordSource  string    `json:"coordSource"`
	Error        string    `json:"error,omitempty"`
	InSbom       *bool     `json:"inSbom"`
	Key          string    `json:"key"`
	Role         string    `json:"role"`
	SupersededBy string    `json:"supersededBy,omitempty"`
	Usage        string    `json:"usage"`
	InUse        bool      `json:"inUse"`
	Users        []User    `json:"users"`
	DeclaredBy   []string  `json:"declaredBy"`
	RequiredBy   []string  `json:"requiredBy"`
	Via          []string  `json:"via"`
	Modules      []string  `json:"modules"`
	Overlaps     []Overlap `json:"overlaps"`
	ClassCount   int       `json:"classCount"`

	classes  []string
	refPkgs  []string
	services []string
	modules  *orderedSet
}

var purlRe = regexp.MustCompile(`(?i)^pkg:maven/([^/]+)/([^@]+)@([^?]+)`)

func parsePurl(purl string) (c coords, ok bool) {
	m := purlRe.FindStringSubmatch(purl)
	if m == nil {
		return c, false
	}
	un := func(s string) string {
		if v, err := url.PathUnescape(s); err == nil {
			return v
		}
		return s
	}
	return coords{un(m[1]), un(m[2]), un(m[3])}, true
}

var actionFile = regexp.MustCompile(`/actions/([^/]+)\.java$`)

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func Analyse(in Input) []*Lib {
	var sbomList []coords
	sbomEdges := map[string]*orderedSet{}
	if in.Sbom != nil {
		for _, c := range in.Sbom.Components {
			if p, ok := parsePurl(c.Purl); ok {
				sbomList = append(sbomList, p)
			} else if c.Group != "" && c.Name != "" {
				sbomList = append(sbomList, coords{c.Group, c.Name, c.Version})
			}
		}
		for _, d := range in.Sbom.Dependencies {
			from, ok := parsePurl(d.Ref)
			if !ok {
				continue
			}
			k := LibraryKey(from.group, from.artifact)
			for _, to := range d.DependsOn {
				if t, ok := parsePurl(to); ok {
					if sbomEdges[k] == nil {
						sbomEdges[k] = newOrderedSet()
					}
					sbomEdges[k].add(LibraryKey(t.group, t.artifact))
				}
			}
		}
	}

	libs := make([]*Lib, 0, len(in.Jars))
	for _, j := range in.Jars {
		info := j.Info
		nameArtifact, nameVersion := CoordsFromFileName(j.Path)
		artifact := firstNonEmpty(info.Artifact, nameArtifact)
		version := firstNonEmpty(info.Version, nameVersion)
		group := info.Group
		coordSource := firstNonEmpty(info.CoordSource, "filename")
		if group == "" {
			if hit := findSbom(sbomList, artifact, version, true); hit != nil {
				group, coordSource = hit.group, "sbom"
			} else if hit := findSbom(sbomList, artifact, "", false); hit != nil {
				group, coordSource = hit.group, "sbom"
			} else {
				for _, d := range in.JarDependencies {
					if d.Artifact == artifact && d.Group != "" {
						group, coordSource = d.Group, "sbom"
						break
					}
				}
			}
		}
		var inSbom *bool
		if in.Sbom != nil {
			v := findSbom(sbomList, artifact, version, true) != nil
			inSbom = &v
		}
		dir, file := j.Path, j.Path
		if i := strings.Index(j.Path, "/"); i >= 0 {
			dir = j.Path[:i]
		}
		file = j.Path[strings.LastIndex(j.Path, "/")+1:]
		libs = append(libs, &Lib{
			Path: j.Path, Dir: dir, File: file, Group: group, Artifact: artifact, Version: version,
			CoordSource: coordSource, Error: info.Error, InSbom: inSbom, Key: LibraryKey(group, artifact),
			Role: "effective", Usage: "unused", Users: []User{}, DeclaredBy: []string{}, RequiredBy: []string{},
			Via: []string{}, Overlaps: []Overlap{},
			classes: info.Classes, refPkgs: info.RefPackages, services: info.Services, modules: newOrderedSet(),
		})
	}

	// Jars without a group merge into the one known library with the same artifact name.
	for _, l := range libs {
		if l.Group != "" {
			continue
		}
		artifactKey := l.Key[strings.Index(l.Key, ":"):]
		same := newOrderedSet()
		for _, x := range libs {
			if x.Group != "" && strings.HasSuffix(x.Key, artifactKey) {
				same.add(x.Key)
			}
		}
		if len(same.items) == 1 {
			l.Key = same.items[0]
		}
	}

	// Newest copy of each library is the effective one, vendorlib before userlib on a tie.
	byKey := map[string][]*Lib{}
	var keyOrder []string
	for _, l := range libs {
		if _, ok := byKey[l.Key]; !ok {
			keyOrder = append(keyOrder, l.Key)
		}
		byKey[l.Key] = append(byKey[l.Key], l)
	}
	for _, k := range keyOrder {
		group := byKey[k]
		sort.SliceStable(group, func(i, j int) bool {
			a, b := group[i], group[j]
			if c := CompareVersions(b.Version, a.Version); c != 0 {
				return c < 0
			}
			return a.Dir != b.Dir && a.Dir == "vendorlib"
		})
		for _, l := range group[1:] {
			if CompareVersions(l.Version, group[0].Version) == 0 {
				l.Role = "duplicate"
			} else {
				l.Role = "superseded"
			}
			l.SupersededBy = group[0].Path
		}
	}
	effective := func(key string) *Lib {
		if g := byKey[key]; len(g) > 0 {
			return g[0]
		}
		return nil
	}

	// Class and package indexes. A class found in several jars goes to the non-superseded ones.
	classIdx := map[string][]*Lib{}
	var classOrder []string
	pkgIdx := map[string][]*Lib{}
	for _, l := range libs {
		for _, c := range l.classes {
			if _, ok := classIdx[c]; !ok {
				classOrder = append(classOrder, c)
			}
			classIdx[c] = append(classIdx[c], l)
			p := PackageOf(c)
			pl := pkgIdx[p]
			if len(pl) == 0 || pl[len(pl)-1] != l {
				pkgIdx[p] = append(pl, l)
			}
		}
	}
	prefer := func(list []*Lib) []*Lib {
		var current []*Lib
		for _, l := range list {
			if l.Role == "effective" {
				current = append(current, l)
			}
		}
		if len(current) > 0 {
			return current
		}
		return list
	}

	// Duplicate classes between jars.
	pairs := map[[2]*Lib]int{}
	var pairOrder [][2]*Lib
	for _, c := range classOrder {
		owners := classIdx[c]
		if len(owners) < 2 {
			continue
		}
		for _, a := range owners {
			for _, b := range owners {
				if a != b {
					k := [2]*Lib{a, b}
					if _, ok := pairs[k]; !ok {
						pairOrder = append(pairOrder, k)
					}
					pairs[k]++
				}
			}
		}
	}
	for _, k := range pairOrder {
		k[0].Overlaps = append(k[0].Overlaps, Overlap{k[1].Path, pairs[k]})
	}

	// Direct references from the app's Java code.
	for _, f := range in.JavaFiles {
		module := moduleOfJava(f.Path, in.ModuleNames)
		action := ""
		if m := actionFile.FindStringSubmatch(f.Path); m != nil {
			action = m[1]
		}
		hit := newLibSet()
		for _, t := range f.Refs.Types {
			hit.addAll(prefer(classIdx[t]))
		}
		for _, p := range f.Refs.Packages {
			hit.addAll(prefer(pkgIdx[p]))
		}
		byName := newLibSet()
		for _, t := range f.Refs.ByName {
			for _, l := range prefer(classIdx[t]) {
				if !hit.has(l) {
					byName.add(l)
				}
			}
		}
		for _, l := range hit.items {
			l.Users = append(l.Users, User{Module: module, File: f.Path, Action: action})
		}
		for _, l := range byName.items {
			l.Users = append(l.Users, User{Module: module, File: f.Path, Action: action, ByName: true})
		}
	}

	for _, d := range in.JarDependencies {
		if l := effective(LibraryKey(d.Group, d.Artifact)); l != nil && !contains(l.DeclaredBy, d.Module) {
			l.DeclaredBy = append(l.DeclaredBy, d.Module)
		}
	}
	for _, r := range in.RequiredLibs {
		for _, l := range libs {
			if strings.EqualFold(l.Path, r.Jar) {
				if !contains(l.RequiredBy, r.Module) {
					l.RequiredBy = append(l.RequiredBy, r.Module)
				}
				break
			}
		}
	}

	// What each jar needs: bytecode package references plus SBOM edges.
	needsCache := map[*Lib][]*Lib{}
	needsOf := func(l *Lib) []*Lib {
		if n, ok := needsCache[l]; ok {
			return n
		}
		out := newLibSet()
		for _, p := range l.refPkgs {
			for _, d := range prefer(pkgIdx[p]) {
				if d != l {
					out.add(d)
				}
			}
		}
		if e := sbomEdges[l.Key]; e != nil {
			for _, k := range e.items {
				if d := effective(k); d != nil && d != l {
					out.add(d)
				}
			}
		}
		needsCache[l] = out.items
		return out.items
	}
	spread := func(roots []*Lib, usage string) {
		queue := append([]*Lib{}, roots...)
		for len(queue) > 0 {
			l := queue[0]
			queue = queue[1:]
			for _, d := range needsOf(l) {
				before := len(d.modules.items)
				for _, m := range l.modules.items {
					d.modules.add(m)
				}
				fresh := d.Usage == "unused"
				if fresh {
					d.Usage = usage
				}
				if (fresh || d.Usage == usage) && !contains(d.Via, l.Path) {
					d.Via = append(d.Via, l.Path)
				}
				if fresh || len(d.modules.items) != before {
					queue = append(queue, d)
				}
			}
		}
	}

	var codeRoots []*Lib
	for _, l := range libs {
		if len(l.Users) > 0 {
			l.Usage = "code"
			for _, u := range l.Users {
				l.modules.add(u.Module)
			}
			codeRoots = append(codeRoots, l)
		}
	}
	spread(codeRoots, "dependency")

	var declaredRoots []*Lib
	for _, l := range libs {
		if len(l.DeclaredBy) > 0 || (len(l.RequiredBy) > 0 && l.Role == "effective") {
			for _, m := range append(append([]string{}, l.DeclaredBy...), l.RequiredBy...) {
				l.modules.add(m)
			}
			if l.Usage == "unused" {
				l.Usage = "declared"
			}
			declaredRoots = append(declaredRoots, l)
		}
	}
	spread(declaredRoots, "declared")

	// ServiceLoader providers: a JDBC driver or logging binding is never named in code.
	var runtimeRoots []*Lib
	for _, l := range libs {
		if l.Usage != "unused" || l.Role != "effective" {
			continue
		}
		for _, iface := range l.services {
			if strings.HasPrefix(iface, "java.") || strings.HasPrefix(iface, "javax.") || anyUsed(prefer(classIdx[iface]), l) {
				runtimeRoots = append(runtimeRoots, l)
				break
			}
		}
	}
	for _, l := range runtimeRoots {
		l.Usage = "runtime"
	}
	spread(runtimeRoots, "runtime")

	for _, l := range libs {
		l.InUse = l.Usage != "unused"
		l.Modules = append([]string{}, l.modules.items...)
		sort.Strings(l.Modules)
		sort.SliceStable(l.Overlaps, func(i, j int) bool { return l.Overlaps[i].Classes > l.Overlaps[j].Classes })
		l.ClassCount = len(l.classes)
	}
	return libs
}

func anyUsed(list []*Lib, self *Lib) bool {
	for _, d := range list {
		if d != self && d.Usage != "unused" {
			return true
		}
	}
	return false
}

func findSbom(list []coords, artifact, version string, matchVersion bool) *coords {
	for i, c := range list {
		if c.artifact == artifact && (!matchVersion || c.version == version) {
			return &list[i]
		}
	}
	return nil
}

func moduleOfJava(filePath string, moduleNames []string) string {
	parts := strings.Split(filePath, "/")
	folder := ""
	if len(parts) > 1 {
		folder = parts[1]
	}
	for _, n := range moduleNames {
		if strings.EqualFold(n, folder) {
			return n
		}
	}
	return folder
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// libSet keeps insertion order, like a JS Set of objects.
type libSet struct {
	seen  map[*Lib]bool
	items []*Lib
}

func newLibSet() *libSet { return &libSet{seen: map[*Lib]bool{}} }

func (s *libSet) add(l *Lib) {
	if !s.seen[l] {
		s.seen[l] = true
		s.items = append(s.items, l)
	}
}
func (s *libSet) addAll(ls []*Lib) {
	for _, l := range ls {
		s.add(l)
	}
}
func (s *libSet) has(l *Lib) bool { return s.seen[l] }
