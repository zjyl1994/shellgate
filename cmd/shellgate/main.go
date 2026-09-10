package main

import (
	"flag"
	"fmt"
	"github.com/zjyl1994/shellgate/internal/app"
	"github.com/zjyl1994/shellgate/internal/mcpserver"
	"github.com/zjyl1994/shellgate/internal/paths"
	"os"
)

const version = "0.1.0"

func main() {
	fs := flag.NewFlagSet("shellgate", flag.ExitOnError)
	data := fs.String("data-dir", "", "ShellGate data directory")
	_ = fs.Parse(os.Args[1:])
	dir, e := paths.DataDir(*data)
	if e != nil {
		fatal(e)
	}
	args := fs.Args()
	cmd := "serve"
	if len(args) > 0 {
		cmd = args[0]
	}
	switch cmd {
	case "init":
		e = app.Init(dir)
	case "check":
		e = app.Check(dir)
	case "version":
		fmt.Println(version)
	case "serve":
		if _, x := os.Stat(dir + "/config.yaml"); os.IsNotExist(x) {
			e = app.Init(dir)
		} else {
			e = app.Serve(dir, mcpserver.Handler)
		}
	default:
		e = fmt.Errorf("unknown command %q", cmd)
	}
	if e != nil {
		fatal(e)
	}
}
func fatal(e error) { fmt.Fprintln(os.Stderr, "shellgate:", e); os.Exit(1) }
