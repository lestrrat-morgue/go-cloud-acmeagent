package localfs

import "errors"

var ErrInvalidID = errors.New("invalid ID: email required")

type StorageOptions struct {
	Root string
	ID   string
}

type Storage struct {
	Root string
	ID   string
}
