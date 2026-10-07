package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/faraga1/mendix-userlib-cleaner/internal/analysis"
	"github.com/faraga1/mendix-userlib-cleaner/internal/app"
	"github.com/tailscale/walk"
	. "github.com/tailscale/walk/declarative"
)

// attachConsole: the exe is built as a GUI program (no console window on double-click);
// when started from a terminal with arguments, write to that terminal instead.
func attachConsole() {
	// Output already redirected (pipe or file): keep writing there.
	if _, err := os.Stdout.Stat(); err == nil {
		return
	}
	const attachParentProcess = ^uint32(0) // (DWORD)-1
	r, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("AttachConsole").Call(uintptr(attachParentProcess))
	if r == 0 {
		return
	}
	if f, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
		os.Stdout, os.Stderr = f, f
	}
}

type row struct {
	entry   analysis.PlanEntry
	checked bool
}

type jarModel struct {
	walk.TableModelBase
	rows []*row
}

func (m *jarModel) RowCount() int { return len(m.rows) }
func (m *jarModel) Value(r, col int) any {
	e := m.rows[r].entry
	switch col {
	case 0:
		return filepath.Base(e.Path)
	case 1:
		return map[string]string{"safe": "Safe", "check": "Check", "orphan": "Orphan (test!)"}[e.Tier]
	default:
		w := e.Why
		if len(e.Markers) > 0 {
			w += fmt.Sprintf("  (+ %d RequiredLib marker%s)", len(e.Markers), map[bool]string{true: "s"}[len(e.Markers) > 1])
		}
		return w
	}
}
func (m *jarModel) Checked(r int) bool             { return m.rows[r].checked }
func (m *jarModel) SetChecked(r int, c bool) error { m.rows[r].checked = c; return nil }

type gui struct {
	mw                             *walk.MainWindow
	detail, status, vendorNote     *walk.Label
	table                          *walk.TableView
	moveBtn, vendorBtn, restoreBtn *walk.PushButton
	model                          *jarModel
	dir                            string
	res                            *result
}

func runGUI() {
	wapp, err := walk.InitApp()
	if err != nil {
		return
	}
	g := &gui{model: &jarModel{}, dir: startDir()}
	err = MainWindow{
		AssignTo: &g.mw,
		Title:    "Mendix userlib cleaner",
		MinSize:  Size{Width: 640, Height: 360},
		Size:     Size{Width: 960, Height: 560},
		Layout:   VBox{},
		Children: []Widget{
			TableView{
				AssignTo:   &g.table,
				CheckBoxes: true,
				Model:      g.model,
				Columns: []TableViewColumn{
					{Title: "Jar in userlib", Width: 250},
					{Title: "Kind", Width: 95},
					{Title: "Why", Width: 560},
				},
				OnCurrentIndexChanged: g.showDetail,
			},
			// Full reason of the selected jar (the table column cuts long ones off).
			Label{AssignTo: &g.detail, Text: " ", TextColor: walk.RGB(80, 80, 80)},
			Label{AssignTo: &g.status, Text: "Ticked jars are moved to a backup folder next to the app (never deleted). vendorlib is never touched."},
			Composite{Layout: HBox{MarginsZero: true}, Children: []Widget{
				Label{AssignTo: &g.vendorNote},
				PushButton{AssignTo: &g.vendorBtn, Text: "vendorlib notes…", OnClicked: g.showVendorlib},
				HSpacer{},
				PushButton{Text: "Other app folder…", OnClicked: g.chooseFolder},
				PushButton{AssignTo: &g.restoreBtn, Text: "Restore a backup…", OnClicked: g.restore},
				PushButton{AssignTo: &g.moveBtn, Text: "Move ticked jars", Enabled: false, OnClicked: g.move},
			}},
		},
	}.Create()
	if err != nil {
		walk.MsgBox(nil, "Userlib cleaner", err.Error(), walk.MsgBoxIconError)
		return
	}
	// walk always creates a toolbar and lays it over the top of the window, but only makes
	// room for it when it has buttons. Ours has none: hide it, or it covers the table header.
	g.mw.ToolBar().SetVisible(false)
	g.vendorBtn.SetVisible(false)
	g.mw.Show()
	if g.dir == "" && !g.pickFolder() {
		return
	}
	g.load()
	wapp.Run()
}

func (g *gui) pickFolder() bool {
	dlg := walk.FileDialog{Title: "Choose the Mendix app folder (the one with the .mpr file)"}
	for {
		ok, err := dlg.ShowBrowseFolder(g.mw)
		if err != nil || !ok {
			return false
		}
		if app.FindMpr(dlg.FilePath) != "" {
			g.dir = dlg.FilePath
			return true
		}
		walk.MsgBox(g.mw, "Userlib cleaner", "There's no .mpr file in that folder. Pick the app folder itself.", walk.MsgBoxIconWarning)
	}
}

func (g *gui) chooseFolder() {
	if g.pickFolder() {
		g.load()
	}
}

// load analyses the app in the background; the window stays responsive.
func (g *gui) load() {
	g.mw.SetTitle(fmt.Sprintf("Mendix userlib cleaner — analysing %s …", filepath.Base(g.dir)))
	g.status.SetText("Reading the jars and Java code …")
	g.moveBtn.SetEnabled(false)
	g.model.rows = nil
	g.model.PublishRowsReset()
	dir := g.dir
	go func() {
		res, err := analyse(dir, false)
		g.mw.Synchronize(func() {
			if err != nil {
				g.mw.SetTitle("Mendix userlib cleaner")
				g.status.SetText("Couldn't read the app.")
				walk.MsgBox(g.mw, "Userlib cleaner", err.Error(), walk.MsgBoxIconError)
				return
			}
			g.show(res)
		})
	}()
}

func (g *gui) show(res *result) {
	g.res = res
	a := res.App
	// App info goes in the title bar (a label above the table gets clipped by walk's layout).
	g.mw.SetTitle(fmt.Sprintf("Mendix userlib cleaner — %s (%s, Studio Pro %s, %d jars, %d Java files)",
		filepath.Base(a.Dir), a.MprFile, orQ(a.MendixVersion), len(a.Input.Jars), len(a.Input.JavaFiles)))
	var rows []*row
	for _, e := range res.Plan.Remove {
		rows = append(rows, &row{entry: e, checked: true})
	}
	for _, e := range res.Plan.Keep {
		rows = append(rows, &row{entry: e})
	}
	g.model.rows = rows
	g.model.PublishRowsReset()
	if len(rows) > 0 {
		_ = g.table.SetCurrentIndex(0)
	}
	g.showDetail()
	switch {
	case len(rows) == 0:
		g.status.SetText("Nothing to clean up in userlib.")
	case len(res.Plan.Keep) > 0:
		g.status.SetText("Safe ones are ticked. Orphans aren't: nothing in the app refers to them, but test the app if you remove them.")
	default:
		g.status.SetText("Ticked jars are moved to a backup folder next to the app (never deleted). vendorlib is never touched.")
	}
	g.moveBtn.SetEnabled(len(rows) > 0)
	if n := len(res.Plan.Vendorlib); n > 0 {
		g.vendorNote.SetText(fmt.Sprintf("vendorlib: %d note%s (not touched)", n, map[bool]string{true: "s"}[n > 1]))
		g.vendorBtn.SetVisible(true)
	} else {
		g.vendorNote.SetText("")
		g.vendorBtn.SetVisible(false)
	}
}

func (g *gui) showDetail() {
	i := g.table.CurrentIndex()
	if i < 0 || i >= len(g.model.rows) {
		g.detail.SetText(" ")
		return
	}
	e := g.model.rows[i].entry
	text := fmt.Sprintf("%s: %s", e.Path, e.Why)
	if len(e.Markers) > 0 {
		text += "; also moves " + strings.Join(e.Markers, ", ")
	}
	g.detail.SetText(text)
}

func (g *gui) move() {
	var selected []analysis.PlanEntry
	orphans := 0
	for _, r := range g.model.rows {
		if r.checked {
			selected = append(selected, r.entry)
			if r.entry.Tier != "safe" {
				orphans++
			}
		}
	}
	if len(selected) == 0 {
		walk.MsgBox(g.mw, "Userlib cleaner", "Tick the jars to move first.", walk.MsgBoxIconInformation)
		return
	}
	msg := fmt.Sprintf("Move %d jar%s (and their RequiredLib markers) out of userlib?\n\nThey go to a backup folder next to the app; nothing is deleted.", len(selected), map[bool]string{true: "s"}[len(selected) > 1])
	if orphans > 0 {
		msg += fmt.Sprintf("\n\n%d of them %s not a safe one: run the app afterwards to check it still works.", orphans, map[bool]string{true: "are", false: "is"}[orphans > 1])
	}
	if walk.MsgBox(g.mw, "Userlib cleaner", msg, walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) != walk.DlgCmdYes {
		return
	}
	backup, err := app.Apply(g.dir, g.res.Plan, selected)
	if err != nil {
		walk.MsgBox(g.mw, "Userlib cleaner", err.Error(), walk.MsgBoxIconError)
		return
	}
	walk.MsgBox(g.mw, "Userlib cleaner", fmt.Sprintf("Done. Backup: %s\n\nNext: in Studio Pro, clean the deployment directory and run the app locally. If it works, review the change in git and commit it.\n\nTo undo: \"Restore a backup…\" and pick that folder.", backup), walk.MsgBoxIconInformation)
	g.load()
}

func (g *gui) restore() {
	dlg := walk.FileDialog{Title: "Choose a userlib backup folder (…-userlib-backup-…)"}
	if g.dir != "" {
		if b := app.FindBackups(g.dir); len(b) > 0 {
			dlg.InitialDirPath = b[0]
		} else {
			dlg.InitialDirPath = filepath.Dir(g.dir)
		}
	}
	if ok, err := dlg.ShowBrowseFolder(g.mw); err != nil || !ok {
		return
	}
	appDir, n, err := app.Restore(dlg.FilePath)
	if err != nil {
		walk.MsgBox(g.mw, "Userlib cleaner", err.Error(), walk.MsgBoxIconError)
		return
	}
	walk.MsgBox(g.mw, "Userlib cleaner", fmt.Sprintf("Restored %d file(s) to %s.", n, appDir), walk.MsgBoxIconInformation)
	if g.dir != "" && strings.EqualFold(filepath.Clean(appDir), filepath.Clean(mustAbs(g.dir))) {
		g.load()
	}
}

func (g *gui) showVendorlib() {
	var b strings.Builder
	b.WriteString("vendorlib is managed by Studio Pro, so the cleaner never touches it. What it found:\r\n\r\n")
	for _, v := range g.res.Plan.Vendorlib {
		fmt.Fprintf(&b, "%s\r\n    %s\r\n    fix: %s\r\n\r\n", v.Path, v.Why, v.Fix)
	}
	var dlg *walk.Dialog
	err := Dialog{
		AssignTo: &dlg,
		Title:    "vendorlib notes",
		MinSize:  Size{Width: 700, Height: 420},
		Layout:   VBox{},
		Children: []Widget{
			TextEdit{Text: b.String(), ReadOnly: true, VScroll: true},
			Composite{Layout: HBox{MarginsZero: true}, Children: []Widget{
				HSpacer{},
				PushButton{Text: "Close", OnClicked: func() { dlg.Accept() }},
			}},
		},
	}.Create(g.mw)
	if err == nil {
		dlg.Run()
	}
}

func mustAbs(p string) string {
	a, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return a
}
