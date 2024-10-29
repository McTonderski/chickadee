package docker

import "context"

// CommandExecutor defines an interface for executing system commands
type CommandExecutor interface {
	ExecCommand(ctx context.Context, command string, args ...string) ([]byte, error)
}
