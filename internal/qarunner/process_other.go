//go:build !unix

package qarunner

import (
	"context"
	"errors"
)

func (s *Server) command(context.Context, *job, string, []string, string, *capture) (int, error) {
	return -1, errors.New("the Karate runner needs a Unix host")
}

func (s *Server) handOver(string) error { return nil }
