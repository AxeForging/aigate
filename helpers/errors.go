package helpers

import "errors"

var (
	ErrNotInitialized   = errors.New("aigate not initialized, run 'aigate init' first")
	ErrAlreadyInit      = errors.New("aigate already initialized")
	ErrPermissionDenied = errors.New("operation requires elevated privileges (sudo)")
	ErrGroupNotFound    = errors.New("sandbox group not found")
	ErrUserNotFound     = errors.New("sandbox user not found")
	ErrInvalidRule      = errors.New("invalid rule")
	ErrCommandBlocked   = errors.New("command is blocked by deny rules")
	ErrConfigNotFound   = errors.New("config file not found")
	ErrUnsupportedOS    = errors.New("unsupported operating system")
)
