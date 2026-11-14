//go:build unix

package qarunner

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// command runs one test process in its own process group, so a timeout or
// cancellation stops the JVM and anything the tests started. It returns the
// exit code; err is set only when the process could not start.
func (s *Server) command(ctx context.Context, j *job, name string, args []string, dir string, console *capture) (int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = s.environment(j)
	cmd.Stdout, cmd.Stderr = console, console
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if s.cfg.JobUID != 0 {
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(s.cfg.JobUID), Gid: uint32(s.cfg.JobGID), NoSetGroups: true}
	}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 15 * time.Second
	err := cmd.Run()
	if cmd.ProcessState == nil {
		return -1, err
	}
	// Reap anything left in the group once the main process exits.
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) && ctx.Err() == nil && !errors.Is(err, exec.ErrWaitDelay) {
		return -1, err
	}
	return cmd.ProcessState.ExitCode(), nil
}

// handOver gives the job user its directory tree when jobs run as another
// user; the runner keeps ownership of the job root.
func (s *Server) handOver(dir string) error {
	if s.cfg.JobUID == 0 {
		return nil
	}
	return filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if p == dir {
			return os.Chmod(p, 0o711)
		}
		return os.Lchown(p, s.cfg.JobUID, s.cfg.JobGID)
	})
}
