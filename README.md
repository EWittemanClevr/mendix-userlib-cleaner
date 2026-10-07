# Mendix userlib cleaner

Finds jars in a Mendix app's `userlib/` folder that the app doesn't use, and moves them out of the way. One ~12 MB Windows
exe with a small window; no runtime needed. Works on Mendix 10 and 11 projects (tested on 10.24, 11.12 and 11.14).

Inspired by [cinaq/mendix-userlib-cleaner](https://github.com/cinaq/mendix-userlib-cleaner), which made "drop an exe in the
project and double-click it" the way to deal with userlib clutter. This one is a separate implementation that looks at more
of the project before deciding a jar can go:

| | cinaq/mendix-userlib-cleaner | this tool |
|---|---|---|
| Looks at | the userlib folder | userlib **and vendorlib** (on Mendix 10+, the newer copy of a library usually sits in vendorlib) |
| Is the jar used? | not checked | checked: Java code in `javasource/` (also class names in strings), module Java dependencies, other jars' bytecode, `vendorlib-sbom.json`, ServiceLoader registrations |
| Identifying a library | `pom.properties`, manifest, file name, or a guess from package names | `pom.properties`, manifest, file name, `vendorlib-sbom.json`; never from package names |
| Same library, different artifact name | — | `bcprov-jdk15on` and `bcprov-jdk18on` count as one library |
| Removing | deletes | moves to a backup folder, with restore |

## Use

1. Close the app in Studio Pro.
2. Put `userlib-cleaner.exe` in the app folder (next to the `.mpr`) and double-click it. Elsewhere, it asks for the app folder.
3. The window lists userlib jars that can go:
   - **Safe** (ticked): an older copy of a library the app also has in a newer version (in vendorlib or userlib), or a
     byte-identical duplicate. Its `.RequiredLib` markers go with it.
   - **Orphan (test!)** (not ticked): nothing refers to it. No Java code (also not by class name in a string), no module Java
     dependency, no other library, no ServiceLoader registration. A class name kept only in a model constant or a config
     file isn't visible, so run the app after removing one.
   - **Check** (not ticked): the same version as another copy, but the files differ.
4. **Move ticked jars** moves them to `<app folder>-userlib-backup-<time>\` next to the app. Nothing is deleted.
   **Restore a backup…** puts them back.
5. In Studio Pro: clean the deployment directory, run the app locally, then review and commit the change.

`vendorlib/` is never touched: Studio Pro manages it. **vendorlib notes…** lists what looks off there (old copies, jars missing
from `vendorlib-sbom.json`) and what to change instead.

It refuses to move anything while the app is open in Studio Pro (`.mpr.lock`) or while `userlib/` has uncommitted git changes,
so a cleanup can always be undone with git as well.

Don't commit the exe: after dropping it in the app folder it shows up as an untracked file. Delete it when you're done, or keep
it one folder up and use **Other app folder…**.

The exe isn't code-signed, so Windows SmartScreen may warn the first time ("More info → Run anyway").

## Download

Get `userlib-cleaner.exe` from the [releases](../../releases), or build it yourself (below).

## Command line

The same exe works from a terminal:

```
userlib-cleaner "C:\Mendix\MyApp"                           dry run; exit code 2 = something to remove
userlib-cleaner "C:\Mendix\MyApp" --apply                   move the safe ones
userlib-cleaner "C:\Mendix\MyApp" --apply --include-orphans
userlib-cleaner --restore "C:\Mendix\MyApp-userlib-backup-20261007-171112"
userlib-cleaner "C:\Mendix\MyApp" --json                    machine-readable plan
```

## How "used" is decided

Per jar, strongest evidence first:

- **code**: a `.java` file in `javasource/` (generated `proxies/` excluded) refers to a class in the jar: imports, wildcard
  imports, fully qualified names, or a class name in a string literal (`Class.forName("org.postgresql.Driver")`).
- **dependency**: the bytecode of a used jar refers to the jar's packages, or `vendorlib-sbom.json` lists it as a dependency.
- **declared**: a module declares it (Module settings → Java dependencies, or a `userlib/<jar>.<Module>.RequiredLib` marker),
  or it's a dependency of such a jar. It may be loaded by reflection, so it counts as used.
- **runtime**: it registers a ServiceLoader provider (`META-INF/services`) for a JDK interface or for a library in use, like a
  JDBC driver.

Two copies of one library (same group and artifact): the newest is the one kept; an older copy only counts as used when code
needs a class that exists in that copy alone.

The model is read straight from the project: the `.mpr` (SQLite) and `mprcontents/` (BSON) for module names and declared Java
dependencies. It only reads; the `.mpr` is opened read-only and immutable.

## Build

Needs Go 1.27+ (`winget install GoLang.Go`).

```
go test ./...
go build -trimpath -ldflags "-s -w -H windowsgui -X main.version=0.1.0" -o userlib-cleaner.exe .
```

`rsrc_windows_amd64.syso` embeds `userlib-cleaner.exe.manifest` (common controls v6 and DPI awareness, needed by the
[tailscale/walk](https://github.com/tailscale/walk) UI). After changing the manifest:
`go run github.com/akavel/rsrc@latest -manifest userlib-cleaner.exe.manifest -o rsrc_windows_amd64.syso`.

GitHub Actions tests and builds every push; pushing a tag like `v0.1.0` publishes the exe as a release.

`testdata/cases.json` holds implementation-neutral test cases for the analysis; add one when you fix a bug.

## License

MIT, see [LICENSE](LICENSE).
