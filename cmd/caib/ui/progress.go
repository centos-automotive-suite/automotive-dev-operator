/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package ui provides terminal progress rendering for build commands.
package ui

import (
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/clilog"
	buildapitypes "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi"
	"golang.org/x/term"
)

// ProgressBar renders build progress. In a TTY it uses \r overwrite with a
// visual bar; in non-TTY mode it prints one line per status change.
// Progress is monotonic: once a higher done count is rendered, lower values
// are ignored to prevent regressions from transient log read failures.
type ProgressBar struct {
	lastLine string
	isTTY    bool
	highStep *buildapitypes.BuildStep // highest progress seen so far
}

// NewProgressBar creates a new progress bar with TTY detection
func NewProgressBar() *ProgressBar {
	return &ProgressBar{isTTY: term.IsTerminal(int(os.Stdout.Fd()))}
}

// Render displays the progress bar with monotonic progress enforcement
func (pb *ProgressBar) Render(phase string, step *buildapitypes.BuildStep) {
	if clilog.IsQuiet() {
		return
	}
	// Work on a local copy to avoid mutating the caller's BuildStep
	var renderStep *buildapitypes.BuildStep
	if step != nil {
		s := *step
		// Enforce monotonic progress: never go backwards in Done or Total
		if pb.highStep != nil {
			if s.Done < pb.highStep.Done {
				s.Done = pb.highStep.Done
			}
			if s.Total < pb.highStep.Total {
				s.Total = pb.highStep.Total
			}
		}
		pb.highStep = &s
		renderStep = &s
	}

	if pb.isTTY {
		pb.renderTTY(phase, renderStep)
	} else {
		pb.renderPlain(phase, renderStep)
	}
}

// renderTTY renders progress with visual bar for TTY terminals
func (pb *ProgressBar) renderTTY(phase string, step *buildapitypes.BuildStep) {
	var line string
	if step == nil {
		line = fmt.Sprintf("\r%-10s ⦿ waiting for progress...", phase)
	} else {
		barWidth := 30
		filled := 0
		if step.Total > 0 {
			filled = min(barWidth, barWidth*step.Done/step.Total)
		}
		bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
		line = fmt.Sprintf("\r%-10s │%s│ %2d/%-2d %s", phase, bar, step.Done, step.Total, step.Stage)
	}
	if line == pb.lastLine {
		return
	}
	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || width <= 0 {
		width = 80
	}
	// Use rune count (not byte length) because the bar contains multi-byte
	// UTF-8 characters (█, ░, │) that are 3 bytes each but 1 display column.
	displayWidth := utf8.RuneCountInString(line) - 1 // subtract 1 for \r
	if displayWidth < width {
		line += strings.Repeat(" ", width-displayWidth)
	}
	_, _ = fmt.Fprint(os.Stdout, line)
	pb.lastLine = line
}

// renderPlain renders progress as plain text for non-TTY output
func (pb *ProgressBar) renderPlain(phase string, step *buildapitypes.BuildStep) {
	var line string
	if step == nil {
		line = fmt.Sprintf("%s: waiting for progress...", phase)
	} else {
		line = fmt.Sprintf("%s: [%d/%d] %s", phase, step.Done, step.Total, step.Stage)
	}
	if line == pb.lastLine {
		return
	}
	fmt.Println(line)
	pb.lastLine = line
}

// Complete renders a fully-filled progress bar and moves to a new line so the
// final state is visible after the build finishes.
func (pb *ProgressBar) Complete() {
	if clilog.IsQuiet() || pb.lastLine == "" {
		return
	}
	total := 8
	if pb.highStep != nil && pb.highStep.Total > 0 {
		total = pb.highStep.Total
	}
	pb.Render("Completed", &buildapitypes.BuildStep{
		Stage: "Complete",
		Done:  total,
		Total: total,
	})
	_, _ = fmt.Fprintln(os.Stdout)
	pb.lastLine = ""
}

// Clear clears the progress bar (TTY mode only)
func (pb *ProgressBar) Clear() {
	if clilog.IsQuiet() || !pb.isTTY || pb.lastLine == "" {
		return
	}
	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || width <= 0 {
		width = 80
	}
	_, _ = fmt.Fprint(os.Stdout, "\r"+strings.Repeat(" ", width)+"\r")
	pb.lastLine = ""
}
