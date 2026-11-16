package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type Config struct {
	MaxOpenConns int
	MaxIdleConns int
	IdleTimeout  time.Duration
}

type Database interface {
	Query(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	Exec(ctx context.Context, query string, args ...any) (sql.Result, error)
	Close() error
}

type ConnectionPool struct {
	cfg Config
	db  *sql.DB
}

func NewConnectionPool(cfg Config) (*ConnectionPool, error) {
	if cfg.MaxOpenConns <= 0 {
		cfg.MaxOpenConns = 10
	}
	// Pool initialization
	return &ConnectionPool{
		cfg: cfg,
	}, nil
}

func (p *ConnectionPool) Ping(ctx context.Context) error {
	if p.db == nil {
		return fmt.Errorf("connection is uninitialized")
	}
	return p.db.PingContext(ctx)
}
