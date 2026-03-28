package sqlite3

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/HT4w5/flux/pkg/dto"
	_ "github.com/mattn/go-sqlite3"
	"go4.org/netipx"
)

const (
	minPruneInterval = time.Minute
)

const (
	tableQuery1 = `CREATE TABLE
    IF NOT EXISTS jail (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        prefix TEXT NOT NULL,
        blame TEXT NOT NULL,
        expires_at DATETIME NOT NULL
    );`
	tableQuery2 = `CREATE INDEX IF NOT EXISTS idx_jail_expires_at ON jail (expires_at);`
)

var (
	ErrShutdown = errors.New("jail shutdown")
)

// Sqlite3Jail implements Jail with sqlite3 database
type Sqlite3Jail struct {
	// External
	logger *slog.Logger

	// Internal
	db           *sql.DB
	shutdownMu   sync.RWMutex // Lock for shutdown
	isShutdown   bool
	cancelWorker context.CancelFunc

	// Statements
	add     *sql.Stmt
	del     *sql.Stmt
	list    *sql.Stmt
	compile *sql.Stmt
	prune   *sql.Stmt

	// Config
	dataSourceName string
	pruneInterval  time.Duration
	banDstPorts    []uint16 // TODO?: add this to dto.BanRecord and decide on analyzer layer
}

func New(opts ...func(*Sqlite3Jail)) *Sqlite3Jail {
	j := &Sqlite3Jail{
		pruneInterval:  time.Hour,
		dataSourceName: "jail.db",
		logger:         slog.New(slog.DiscardHandler),
		banDstPorts:    []uint16{80, 443},
	}

	for _, opt := range opts {
		opt(j)
	}

	if j.pruneInterval < minPruneInterval {
		j.pruneInterval = minPruneInterval
	}

	return j
}

// WithLogger sets the logger for the Sqlite3Jail.
func WithLogger(logger *slog.Logger) func(*Sqlite3Jail) {
	return func(j *Sqlite3Jail) {
		j.logger = logger
	}
}

// WithDataSourceName sets the data source name for the SQLite database.
func WithDataSourceName(dataSourceName string) func(*Sqlite3Jail) {
	return func(j *Sqlite3Jail) {
		j.dataSourceName = dataSourceName
	}
}

// WithPruneInterval sets the prune interval for cleaning up expired records.
// The interval will be clamped to minPruneInterval if a smaller value is provided.
func WithPruneInterval(interval time.Duration) func(*Sqlite3Jail) {
	return func(j *Sqlite3Jail) {
		j.pruneInterval = interval
	}
}

// WithBanDstPorts sets the destination ports to ban.
func WithBanDstPorts(ports []uint16) func(*Sqlite3Jail) {
	return func(j *Sqlite3Jail) {
		j.banDstPorts = ports
	}
}

func (j *Sqlite3Jail) Init(ctx context.Context) error {
	j.logger.Info("starting sqlite3 jail")
	var err error
	j.db, err = sql.Open("sqlite3", j.dataSourceName+"?_journal_mode=WAL&_busy_timeout=5000&parseTime=true")
	if err != nil {
		return err
	}

	workerCtx, cancel := context.WithCancel(ctx)
	j.cancelWorker = cancel

	// Create table if not exist
	_, err = j.db.ExecContext(ctx, tableQuery1)
	if err != nil {
		goto FailureClose
	}

	_, err = j.db.ExecContext(ctx, tableQuery2)
	if err != nil {
		goto FailureClose
	}

	// Init statements
	j.add, err = j.db.PrepareContext(ctx, `INSERT INTO jail (prefix, blame, expires_at) VALUES (?, ?, ?)`)
	if err != nil {
		goto FailureClose
	}
	j.del, err = j.db.PrepareContext(ctx, `DELETE FROM jail WHERE id = ?`)
	if err != nil {
		goto FailureClose
	}
	j.list, err = j.db.PrepareContext(ctx, `SELECT id, prefix, blame, expires_at FROM jail WHERE expires_at > ?`)
	if err != nil {
		goto FailureClose
	}
	j.compile, err = j.db.PrepareContext(ctx, `SELECT prefix FROM jail WHERE expires_at > ?`)
	if err != nil {
		goto FailureClose
	}
	j.prune, err = j.db.PrepareContext(ctx, `DELETE FROM jail WHERE expires_at <= ?`)
	if err != nil {
		goto FailureClose
	}

	go j.worker(workerCtx)
	return nil

FailureClose:
	j.Close()
	return err
}

func (j *Sqlite3Jail) Close() error {
	j.logger.Info("closing")
	j.shutdownMu.Lock()
	defer j.shutdownMu.Unlock()
	if j.isShutdown {
		return nil
	}
	j.isShutdown = true

	// Cancel worker
	if j.cancelWorker != nil {
		j.cancelWorker()
	}

	// Close statements
	var err error
	if j.add != nil {
		err = j.add.Close()
	}
	if j.del != nil {
		err = errors.Join(err, j.del.Close())
	}
	if j.list != nil {
		err = errors.Join(err, j.list.Close())
	}
	if j.compile != nil {
		err = errors.Join(err, j.compile.Close())
	}
	if j.prune != nil {
		err = errors.Join(err, j.prune.Close())
	}
	if j.db != nil {
		err = errors.Join(err, j.db.Close())
	}
	if err != nil {
		j.logger.Warn("failed to close db", "error", err)
	}
	return err
}

func (j *Sqlite3Jail) Add(ctx context.Context, b *dto.BanRecord) error {
	j.shutdownMu.RLock()
	defer j.shutdownMu.RUnlock()
	if j.isShutdown {
		return ErrShutdown
	}
	_, err := j.add.ExecContext(ctx, b.Prefix.String(), b.Blame, b.ExpiresAt)
	return err
}

func (j *Sqlite3Jail) Del(ctx context.Context, id int64) error {
	j.shutdownMu.RLock()
	defer j.shutdownMu.RUnlock()
	if j.isShutdown {
		return ErrShutdown
	}
	_, err := j.del.ExecContext(ctx, id)
	return err
}

func (j *Sqlite3Jail) List(ctx context.Context) ([]dto.BanRecord, error) {
	j.shutdownMu.RLock()
	defer j.shutdownMu.RUnlock()
	if j.isShutdown {
		return nil, ErrShutdown
	}

	rows, err := j.list.QueryContext(ctx, time.Now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var bans []dto.BanRecord
	for rows.Next() {
		var b dto.BanRecord
		var prefixStr string
		if err := rows.Scan(&b.ID, &prefixStr, &b.Blame, &b.ExpiresAt); err != nil {
			return nil, err
		}

		if p, err := netip.ParsePrefix(prefixStr); err == nil {
			b.Prefix = p
		} else {
			j.logger.Warn("failed to parse ban prefix", "error", err, "prefix", prefixStr)
			continue
		}
		bans = append(bans, b)
	}
	return bans, nil
}

func (j *Sqlite3Jail) Compile(ctx context.Context) ([]dto.BanRule, error) {
	j.shutdownMu.RLock()
	defer j.shutdownMu.RUnlock()
	if j.isShutdown {
		return nil, ErrShutdown
	}

	rows, err := j.compile.QueryContext(ctx, time.Now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ipsb netipx.IPSetBuilder

	for rows.Next() {
		var prefixStr string
		if err := rows.Scan(&prefixStr); err != nil {
			return nil, err
		}

		if p, err := netip.ParsePrefix(prefixStr); err == nil {
			ipsb.AddPrefix(p)
		} else {
			j.logger.Warn("failed to parse ban prefix", "error", err, "prefix", prefixStr)
			continue
		}
	}

	ips, err := ipsb.IPSet()
	if err != nil {
		j.logger.Warn("ipset build error", "error", err)
	}

	return []dto.BanRule{
		{
			Prefixes: ips.Prefixes(),
			DstPorts: j.banDstPorts,
		},
	}, nil
}

// Cleanup removes all expired records from the database
func (j *Sqlite3Jail) worker(ctx context.Context) {
	ticker := time.NewTicker(j.pruneInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			goto Exit
		case <-ticker.C:
			j.logger.Info("pruning expired")
			j.shutdownMu.RLock()
			if j.isShutdown {
				j.shutdownMu.RUnlock()
				goto Exit
			}
			_, err := j.prune.ExecContext(ctx, time.Now())
			j.shutdownMu.RUnlock()
			if err != nil {
				j.logger.Warn("prune failed", "error", err)
			}
		}
	}

Exit:
	j.logger.Info("worker exit")
}
