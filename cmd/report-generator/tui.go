package main

import (
	"fmt"
	"math"
	"sort"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

//
// ===== Styling =====
//

var (
	lowCovStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff5555"))
	medCovStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#f1fa8c"))
	highCovStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#50fa7b"))

	fileOpenStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#8be9fd"))
	fileClosedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#6272a4"))

	headerStyle = lipgloss.NewStyle().Bold(true)

	selectedRowStyle = lipgloss.NewStyle().
				Background(lipgloss.Color("#44475a")).
				Foreground(lipgloss.Color("#f8f8f2"))
)

func styleCoverage(p float64) string {
	txt := fmt.Sprintf("%5.1f%%", p)
	switch {
	case p < 50:
		return lowCovStyle.Render(txt)
	case p < 80:
		return medCovStyle.Render(txt)
	default:
		return highCovStyle.Render(txt)
	}
}

//
// ===== Entry model =====
//

type entryType int

const (
	entryDir entryType = iota
	entryFile
)

type entry struct {
	kind     entryType
	name     string
	node     *Node
	opened   bool
	coverage float64
}

//
// ===== Bubble Tea model =====
//

type Model struct {
	report *Report

	curr *Node
	path []string

	entries []entry
	cursor  int
	offset  int // scroll offset

	width  int
	height int
}

//
// ===== Constructor =====
//

func New(report *Report) Model {
	m := Model{
		report: report,
		curr:   report.Root,
	}
	m.refresh()
	return m
}

//
// ===== Coverage logic =====
//

func coverage(n *Node) (opened, total int) {
	for _, v := range n.Files {
		total++
		if v {
			opened++
		}
	}
	for _, d := range n.Directories {
		o, t := coverage(d)
		opened += o
		total += t
	}
	return
}

func coveragePercent(n *Node) float64 {
	o, t := coverage(n)
	if t == 0 {
		return 100
	}
	return float64(o) / float64(t) * 100
}

//
// ===== Refresh directory =====
//

func (m *Model) refresh() {
	var entries []entry

	var dirNames []string
	for name := range m.curr.Directories {
		dirNames = append(dirNames, name)
	}
	sort.Strings(dirNames)

	for _, name := range dirNames {
		n := m.curr.Directories[name]
		entries = append(entries, entry{
			kind:     entryDir,
			name:     name,
			node:     n,
			coverage: coveragePercent(n),
		})
	}

	var fileNames []string
	for name := range m.curr.Files {
		fileNames = append(fileNames, name)
	}
	sort.Strings(fileNames)

	for _, name := range fileNames {
		entries = append(entries, entry{
			kind:   entryFile,
			name:   name,
			opened: m.curr.Files[name],
		})
	}

	m.entries = entries
	m.cursor = 0
	m.offset = 0
}

//
// ===== Bubble Tea =====
//

func (m Model) Init() tea.Cmd {
	return nil
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tea.KeyMsg:
		switch msg.String() {

		case "ctrl+c", "q":
			return m, tea.Quit

		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
				m.adjustOffset()
			}

		case "down", "j":
			if m.cursor < len(m.entries)-1 {
				m.cursor++
				m.adjustOffset()
			}

		case "enter", "right", "l":
			e := m.entries[m.cursor]
			if e.kind == entryDir {
				m.path = append(m.path, e.name)
				m.curr = e.node
				m.refresh()
			}

		case "left", "h", "backspace":
			if len(m.path) > 0 {
				m.path = m.path[:len(m.path)-1]
				m.curr = m.report.Root
				for _, p := range m.path {
					m.curr = m.curr.Directories[p]
				}
				m.refresh()
			}
		}
	}

	return m, nil
}

//
// ===== View =====
//

func (m Model) View() string {
	if m.width == 0 || m.height == 0 {
		return "loading…"
	}

	var s string

	// Header
	pathStr := "/"
	for _, p := range m.path {
		pathStr += p + "/"
	}
	s += headerStyle.Render("Path: "+pathStr) + "\n\n"

	headerHeight := 2
	footerHeight := 2
	visibleRows := m.height - headerHeight - footerHeight
	if visibleRows < 1 {
		visibleRows = 1
	}

	start := m.offset
	end := min(start+visibleRows, len(m.entries))

	nameWidth := int(math.Max(20, float64(m.width)*0.6))
	statusWidth := 10

	for i := start; i < end; i++ {
		e := m.entries[i]
		var line string

		switch e.kind {

		case entryDir:
			line = fmt.Sprintf(
				" 📁 %-*s %s",
				nameWidth,
				e.name,
				styleCoverage(e.coverage),
			)

		case entryFile:
			status := fileClosedStyle.Render("closed")
			if e.opened {
				status = fileOpenStyle.Render("opened")
			}

			line = fmt.Sprintf(
				" 📄 %-*s %-*s",
				nameWidth,
				e.name,
				statusWidth,
				status,
			)
		}

		if i == m.cursor {
			line = selectedRowStyle.Render(line)
		}

		s += line + "\n"
	}

	s += "\n↑↓ navigate • enter open • ← back • q quit\n"
	return s
}

//
// ===== Scrolling logic =====
//

func (m *Model) adjustOffset() {
	visibleRows := m.height - 4
	if visibleRows < 1 {
		return
	}

	if m.cursor < m.offset {
		m.offset = m.cursor
	} else if m.cursor >= m.offset+visibleRows {
		m.offset = m.cursor - visibleRows + 1
	}

	if m.offset < 0 {
		m.offset = 0
	}
}

//
// ===== Helpers =====
//

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
