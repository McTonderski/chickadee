package docker

import (
	"context"
	"errors"
	"strings"
)

// MockCommandExecutor simulates command execution for testing
type MockCommandExecutor struct {
	CommandOutputs map[string]string // Command -> Output
	FailCommands   map[string]bool   // Command -> ShouldFail
}

// ExecCommand simulates executing a command by returning predefined output or error
func (m *MockCommandExecutor) ExecCommand(ctx context.Context, command string, args ...string) ([]byte, error) {
	fullCommand := command + " " + strings.Join(args, " ")
	if m.FailCommands[fullCommand] {
		return nil, errors.New("command failed: " + fullCommand)
	}
	if output, exists := m.CommandOutputs[fullCommand]; exists {
		return []byte(output), nil
	}
	return nil, errors.New("unknown command: " + fullCommand)
}
