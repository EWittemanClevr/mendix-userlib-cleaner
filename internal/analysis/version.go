package analysis

import (
	"strconv"
	"strings"
)

// Version order: "major.minor.patch" with an optional "-suffix";
// missing parts count as 0; a suffixed version sorts before the same unsuffixed one;
// invalid versions sort first.

type parsedVersion struct {
	nums   []int
	suffix string
	valid  bool
}

func parseVersion(v string) parsedVersion {
	s := strings.TrimSpace(v)
	core, suffix, _ := strings.Cut(s, "-")
	parts := strings.Split(core, ".")
	nums := make([]int, len(parts))
	valid := s != ""
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || p == "" || strings.ContainsAny(p, "+- ") {
			valid = false
		}
		nums[i] = n
	}
	return parsedVersion{nums, suffix, valid}
}

// CompareVersions returns -1 if a < b, 0 if equal, 1 if a > b.
func CompareVersions(a, b string) int {
	pa, pb := parseVersion(a), parseVersion(b)
	if !pa.valid || !pb.valid {
		switch {
		case pa.valid == pb.valid:
			return 0
		case pa.valid:
			return 1
		default:
			return -1
		}
	}
	for i := 0; i < max(len(pa.nums), len(pb.nums)); i++ {
		x, y := at(pa.nums, i), at(pb.nums, i)
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	switch {
	case pa.suffix == pb.suffix:
		return 0
	case pa.suffix == "":
		return 1
	case pb.suffix == "":
		return -1
	case pa.suffix < pb.suffix:
		return -1
	default:
		return 1
	}
}

func at(s []int, i int) int {
	if i < len(s) {
		return s[i]
	}
	return 0
}
