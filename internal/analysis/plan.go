package analysis

// What may be removed. Only userlib/ is ever touched; vendorlib/ is
// managed by Studio Pro, so problems there are reported with what to change instead.
//   safe    older copy of a library that's also present in a newer version, or a
//           byte-identical copy of one that's present elsewhere
//   check   same version elsewhere, but the bytes differ
//   orphan  nothing refers to it; only removed when asked, and the app must be tested
// A jar's .RequiredLib markers go with it.

import (
	"fmt"
	"strings"
)

type PlanEntry struct {
	Path     string   `json:"path"`
	Version  string   `json:"version"`
	Group    string   `json:"group"`
	Artifact string   `json:"artifact"`
	Tier     string   `json:"tier"`
	Why      string   `json:"why"`
	Markers  []string `json:"markers"`
}

type VendorlibNote struct {
	Path   string `json:"path"`
	InSbom *bool  `json:"inSbom"`
	Why    string `json:"why"`
	Fix    string `json:"fix"`
}

type Plan struct {
	Remove    []PlanEntry     `json:"remove"`
	Keep      []PlanEntry     `json:"keep"`
	Vendorlib []VendorlibNote `json:"vendorlib"`
}

func MakePlan(results []*Lib, requiredLibs []RequiredLib, sha256 map[string]string, includeOrphans bool) Plan {
	byPath := map[string]*Lib{}
	for _, l := range results {
		byPath[l.Path] = l
	}
	markersOf := func(jar string) []string {
		out := []string{}
		for _, r := range requiredLibs {
			if strings.EqualFold(r.Jar, jar) {
				m := r.Marker
				if m == "" {
					m = fmt.Sprintf("%s.%s.RequiredLib", r.Jar, r.Module)
				}
				out = append(out, m)
			}
		}
		return out
	}
	plan := Plan{Remove: []PlanEntry{}, Keep: []PlanEntry{}, Vendorlib: []VendorlibNote{}}
	for _, l := range results {
		other := byPath[l.SupersededBy]
		if l.Dir == "vendorlib" {
			if l.InUse {
				continue
			}
			// The SBOM is what Studio Pro last resolved; a copy missing from it is likely a leftover.
			sbomNote := ""
			if l.InSbom != nil && !*l.InSbom {
				sbomNote = "; not in vendorlib-sbom.json (likely a leftover)"
			} else if l.InSbom != nil && *l.InSbom && other != nil && other.Dir == "vendorlib" && other.InSbom != nil && !*other.InSbom {
				sbomNote = fmt.Sprintf("; but the SBOM lists this version, not %s", other.Version)
			}
			why := "nothing uses it"
			if l.SupersededBy != "" {
				why = "older than " + l.SupersededBy
				if other != nil && other.Dir == "userlib" {
					why += " (a hand-added userlib copy wins; consider removing that one and letting the module manage it)"
				}
			}
			fix := "pulled in by a module dependency: update the module that pins this version in Studio Pro"
			if sbomNote != "" {
				fix = "vendorlib and vendorlib-sbom.json disagree: let Studio Pro re-resolve the managed dependencies (rebuild the app) and commit what changes in vendorlib"
			} else if len(l.DeclaredBy) > 0 {
				fix = fmt.Sprintf("a module declares it (%s): update or adjust that module's Java dependencies", strings.Join(l.DeclaredBy, ", "))
			}
			plan.Vendorlib = append(plan.Vendorlib, VendorlibNote{Path: l.Path, InSbom: l.InSbom, Why: why + sbomNote, Fix: fix})
			continue
		}
		if l.InUse {
			continue
		}
		var tier, why string
		switch l.Role {
		case "superseded":
			ov := "?"
			if other != nil {
				ov = other.Version
			}
			tier, why = "safe", fmt.Sprintf("older copy (%s); %s (%s) is newer", l.Version, l.SupersededBy, ov)
		case "duplicate":
			if sha256[l.Path] != "" && sha256[l.Path] == sha256[l.SupersededBy] {
				tier, why = "safe", "byte-identical to "+l.SupersededBy
			} else {
				tier, why = "check", fmt.Sprintf("same version as %s, but the files differ", l.SupersededBy)
			}
		default:
			tier, why = "orphan", "nothing refers to it (code, strings, modules, other libraries, ServiceLoader)"
		}
		if len(l.RequiredBy) > 0 {
			why += "; stale RequiredLib marker for " + strings.Join(l.RequiredBy, ", ")
		}
		e := PlanEntry{Path: l.Path, Version: l.Version, Group: l.Group, Artifact: l.Artifact, Tier: tier, Why: why, Markers: markersOf(l.Path)}
		if tier == "safe" || (includeOrphans && tier == "orphan") {
			plan.Remove = append(plan.Remove, e)
		} else {
			plan.Keep = append(plan.Keep, e)
		}
	}
	return plan
}
