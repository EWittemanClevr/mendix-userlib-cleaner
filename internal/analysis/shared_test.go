package analysis

// Runs testdata/cases.json. A JavaScript implementation of the same analysis (in a
// private dashboard project) runs these cases too, so keep them implementation-neutral.

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

type sharedCases struct {
	Java []struct {
		Name     string   `json:"name"`
		Src      string   `json:"src"`
		Types    []string `json:"types"`
		Packages []string `json:"packages"`
		ByName   []string `json:"byName"`
	} `json:"java"`
	Analysis []struct {
		Name  string `json:"name"`
		Input struct {
			Jars []struct {
				Path string  `json:"path"`
				Info JarInfo `json:"info"`
			} `json:"jars"`
			JavaFiles []struct {
				Path string   `json:"path"`
				Refs JavaRefs `json:"refs"`
			} `json:"javaFiles"`
			JarDependencies []JarDependency `json:"jarDependencies"`
			RequiredLibs    []RequiredLib   `json:"requiredLibs"`
			ModuleNames     []string        `json:"moduleNames"`
		} `json:"input"`
		Sha256 map[string]string `json:"sha256"`
		Libs   map[string]struct {
			Usage        string   `json:"usage"`
			Role         string   `json:"role"`
			SupersededBy *string  `json:"supersededBy"`
			Users        []string `json:"users"`
			Via          []string `json:"via"`
			Modules      []string `json:"modules"`
		} `json:"libs"`
		Plan struct {
			Remove    []string            `json:"remove"`
			Keep      [][2]string         `json:"keep"`
			Vendorlib []string            `json:"vendorlib"`
			Markers   map[string][]string `json:"markers"`
		} `json:"plan"`
		PlanWithOrphans *struct {
			Remove []string `json:"remove"`
		} `json:"planWithOrphans"`
	} `json:"analysis"`
}

func loadCases(t *testing.T) sharedCases {
	raw, err := os.ReadFile("../../testdata/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var c sharedCases
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func eq(t *testing.T, what string, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s: got %#v, want %#v", what, got, want)
	}
}

func TestSharedJavaCases(t *testing.T) {
	for _, c := range loadCases(t).Java {
		t.Run(c.Name, func(t *testing.T) {
			r := ParseJavaSource(c.Src)
			eq(t, "types", r.Types, c.Types)
			eq(t, "packages", r.Packages, c.Packages)
			eq(t, "byName", r.ByName, c.ByName)
		})
	}
}

func TestSharedAnalysisCases(t *testing.T) {
	for _, c := range loadCases(t).Analysis {
		t.Run(c.Name, func(t *testing.T) {
			in := Input{JarDependencies: c.Input.JarDependencies, RequiredLibs: c.Input.RequiredLibs, ModuleNames: c.Input.ModuleNames}
			for _, j := range c.Input.Jars {
				in.Jars = append(in.Jars, Jar{Path: j.Path, BlobSha: j.Path, Info: j.Info})
			}
			for _, f := range c.Input.JavaFiles {
				in.JavaFiles = append(in.JavaFiles, JavaFile{Path: f.Path, Refs: f.Refs})
			}
			libs := Analyse(in)
			byPath := map[string]*Lib{}
			for _, l := range libs {
				byPath[l.Path] = l
			}
			for path, want := range c.Libs {
				l := byPath[path]
				if l == nil {
					t.Fatalf("%s missing", path)
				}
				eq(t, path+" usage", l.Usage, want.Usage)
				eq(t, path+" role", l.Role, want.Role)
				if want.SupersededBy != nil {
					eq(t, path+" supersededBy", l.SupersededBy, *want.SupersededBy)
				}
				if want.Users != nil {
					var users []string
					for _, u := range l.Users {
						s := u.Module + ":" + firstNonEmpty(u.Action, u.File)
						if u.ByName {
							s += ":byName"
						}
						users = append(users, s)
					}
					eq(t, path+" users", users, want.Users)
				}
				if want.Via != nil {
					eq(t, path+" via", l.Via, want.Via)
				}
				if want.Modules != nil {
					eq(t, path+" modules", l.Modules, want.Modules)
				}
			}
			plan := MakePlan(libs, c.Input.RequiredLibs, c.Sha256, false)
			paths := func(es []PlanEntry) []string {
				out := []string{}
				for _, e := range es {
					out = append(out, e.Path)
				}
				return out
			}
			eq(t, "remove", paths(plan.Remove), c.Plan.Remove)
			keep := [][2]string{}
			for _, e := range plan.Keep {
				keep = append(keep, [2]string{e.Path, e.Tier})
			}
			eq(t, "keep", keep, append([][2]string{}, c.Plan.Keep...))
			vl := []string{}
			for _, v := range plan.Vendorlib {
				vl = append(vl, v.Path)
			}
			eq(t, "vendorlib", vl, c.Plan.Vendorlib)
			for p, want := range c.Plan.Markers {
				for _, e := range plan.Remove {
					if e.Path == p {
						eq(t, p+" markers", e.Markers, want)
					}
				}
			}
			if c.PlanWithOrphans != nil {
				eq(t, "remove with orphans", paths(MakePlan(libs, c.Input.RequiredLibs, c.Sha256, true).Remove), c.PlanWithOrphans.Remove)
			}
		})
	}
}

func TestCompareVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{{"1.10", "1.9", 1}, {"33.5.0-jre", "33.4.8-jre", 1}, {"2.0.0-beta", "2.0.0", -1}, {"", "1.0", -1}, {"1.0", "1.0.0", 0}} {
		eq(t, c.a+" vs "+c.b, CompareVersions(c.a, c.b), c.want)
	}
}

func TestClassFileRefs(t *testing.T) {
	// cp: #1 Utf8 "a/B", #2 Class #1, #3 Utf8 "(Lorg/x/Y;)V", #4 Long (two slots)
	utf := func(s string) []byte { return append([]byte{1, 0, byte(len(s))}, s...) }
	buf := []byte{0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52, 0, 6}
	buf = append(buf, utf("a/B")...)
	buf = append(buf, 7, 0, 1)
	buf = append(buf, utf("(Lorg/x/Y;)V")...)
	buf = append(buf, 5, 0, 0, 0, 0, 0, 0, 0, 1)
	eq(t, "refs", ClassFileRefs(buf), []string{"a/B", "org/x/Y"})
}
