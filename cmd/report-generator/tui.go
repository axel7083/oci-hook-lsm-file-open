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
	file     *FileInfo
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
	offset  int

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
// ===== Coverage logic (byte-based) =====
//

func coveragePercent(n *Node) float64 {
	if n.TotalSize == 0 {
		return 100
	}
	return float64(n.OpenedSize) / float64(n.TotalSize) * 100
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
		fi := m.curr.Files[name]
		entries = append(entries, entry{
			kind: entryFile,
			name: name,
			file: &fi,
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

	// ----- Header -----
	pathStr := "/"
	for _, p := range m.path {
		pathStr += p + "/"
	}
	header := headerStyle.Render("Path: "+pathStr) + "\n\n"

	headerHeight := 2
	footerHeight := 2
	visibleRows := m.height - headerHeight - footerHeight
	if visibleRows < 1 {
		visibleRows = 1
	}

	start := m.offset
	end := min(start+visibleRows, len(m.entries))

	nameWidth := int(math.Max(20, float64(m.width)*0.5))
	sizeWidth := 10
	statusWidth := 10

	// ----- Body (scrollable) -----
	var body string
	for i := start; i < end; i++ {
		e := m.entries[i]
		var line string

		switch e.kind {

		case entryDir:
			line = fmt.Sprintf(
				" 📁 %-*s %*s %s",
				nameWidth,
				e.name,
				sizeWidth,
				humanSize(e.node.TotalSize),
				styleCoverage(e.coverage),
			)

		case entryFile:
			status := fileClosedStyle.Render("unused")
			if e.file.Accessed {
				status = fileOpenStyle.Render("opened")
			}

			line = fmt.Sprintf(
				" 📄 %-*s %*s %-*s",
				nameWidth,
				e.name,
				sizeWidth,
				humanSize(e.file.Size),
				statusWidth,
				status,
			)
		}

		if i == m.cursor {
			line = selectedRowStyle.Render(line)
		}

		body += line + "\n"
	}

	// ----- Footer -----
	footer := "\n↑↓ navigate • enter open • ← back • q quit"

	return header + body + footer
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

func humanSize(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
