// Command portkill finds the process listening on a port and frees it.
package main

import (
	"os"
	"runtime"
	"time"

	"github.com/Mr-hunt-007/portkill/internal/app"
	"github.com/Mr-hunt-007/portkill/internal/sys"
)

func main() {
	home, _ := os.UserHomeDir()
	env := app.Env{
		Sys:         sys.OS{},
		Stdin:       os.Stdin,
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		StdinTTY:    sys.IsTerminal(os.Stdin),
		StdoutTTY:   sys.IsTerminal(os.Stdout),
		Getenv:      os.Getenv,
		Now:         time.Now,
		Sleep:       time.Sleep,
		GOOS:        runtime.GOOS,
		Home:        home,
		ParseSignal: sys.ParseSignal,
	}
	os.Exit(app.Run(os.Args[1:], env))
}
