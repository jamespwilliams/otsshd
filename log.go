package main

import (
	"fmt"
	"time"

	"github.com/fatih/color"
)

func formatNow() string {
	return time.Now().Format(time.RFC3339)
}

func logNotice(s string) {
	color.New(color.FgMagenta).Print(formatNow())
	color.New(color.FgBlue, color.Bold).Print(" notice:\t\t")
	color.New(color.FgBlue).Println(s)
}

func logSuccess(s string) {
	fmt.Println()
	color.New(color.FgMagenta).Print(formatNow())
	color.New(color.FgGreen, color.Bold).Println(" " + s)
}

func logError(s string) {
	color.New(color.FgMagenta).Print(formatNow())
	color.New(color.FgRed, color.Bold).Print(" error:\t\t")
	color.New(color.FgRed, color.Bold).Println(s)
}

func logWarn(s string) {
	color.New(color.FgMagenta).Print(formatNow())
	color.New(color.FgYellow, color.Bold).Print(" warning:\t\t")
	color.New(color.FgYellow, color.Bold).Println(s)
}
