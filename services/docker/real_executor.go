package docker

import (
	"bytes"
	"context"
	"os/exec"
)

// RealCommandExecutor is the actual implementation of CommandExecutor that uses exec.Command
type RealCommandExecutor struct{}

// ExecCommand executes the given command and returns its output or an error
func (e *RealCommandExecutor) ExecCommand(ctx context.Context, command string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, command, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.Bytes(), err
}
