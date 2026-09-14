// Command sba audits the local system against a security baseline.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := cli.New(os.Stdout, os.Stderr).Run(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}
