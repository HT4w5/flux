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
        addr TEXT PRIMARY KEY,
        blame TEXT NOT NULL,
        expires_at DATETIME NOT NULL
    ) WITHOUT ROWID;`
	tableQuery2 = `CREATE INDEX IF NOT EXISTS idx_jail_expires_at ON jail (expires_at);`
)

var (
	ErrShutdown = errors.New("jail shutdown")
)

// SQLite3Jail implements Jail with sqlite3 database
type SQLite3Jail struct {
	db             *sql.DB
	cancelWorker   context.CancelFunc
	prune          *sql.Stmt
	del            *sql.Stmt
	list           *sql.Stmt
	compile        *sql.Stmt
	addSelect      *sql.Stmt
	addInsert      *sql.Stmt
	addUpdate      *sql.Stmt
	logger         *slog.Logger
	dataSourceName string
	banDstPorts    []uint16 // TODO?: add this to dto.BanRecord and decide on analyzer layer
	pruneInterval  time.Duration
	shutdownMu     sync.RWMutex // Lock at shutdown
	ipv4PrefixLen  int
	ipv6PrefixLen  int
	isShutdown     bool
}

func New(opts ...func(*SQLite3Jail)) *SQLite3Jail {
	j := &SQLite3Jail{
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

// WithLogger sets the logger for the SQLite3Jail.
func WithLogger(logger *slog.Logger) func(*SQLite3Jail) {
	return func(j *SQLite3Jail) {
		j.logger = logger
	}
}

// WithDataSourceName sets the data source name for the SQLite database.
func WithDataSourceName(dataSourceName string) func(*SQLite3Jail) {
	return func(j *SQLite3Jail) {
		j.dataSourceName = dataSourceName
	}
}

// WithPruneInterval sets the prune interval for cleaning up expired records.
// The interval will be clamped to minPruneInterval if a smaller value is provided.
func WithPruneInterval(interval time.Duration) func(*SQLite3Jail) {
	return func(j *SQLite3Jail) {
		j.pruneInterval = interval
	}
}

// WithBanDstPorts sets the destination ports to ban.
func WithBanDstPorts(ports []uint16) func(*SQLite3Jail) {
	return func(j *SQLite3Jail) {
		j.banDstPorts = ports
	}
}

// WithIPv4BanPrefixLength sets the prefix length for IPv4 addresses when compiling ban rules.
func WithIPv4BanPrefixLength(prefixLen int) func(*SQLite3Jail) {
	return func(j *SQLite3Jail) {
		j.ipv4PrefixLen = prefixLen
	}
}

// WithIPv6BanPrefixLength sets the prefix length for IPv6 addresses when compiling ban rules.
func WithIPv6BanPrefixLength(prefixLen int) func(*SQLite3Jail) {
	return func(j *SQLite3Jail) {
		j.ipv6PrefixLen = prefixLen
	}
}

func (j *SQLite3Jail) Start() error {
	ctx := context.TODO()
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
	j.del, err = j.db.PrepareContext(ctx, `DELETE FROM jail WHERE addr = ?`)
	if err != nil {
		goto FailureClose
	}
	j.list, err = j.db.PrepareContext(ctx, `SELECT addr, blame, expires_at FROM jail WHERE expires_at > ?`)
	if err != nil {
		goto FailureClose
	}
	j.compile, err = j.db.PrepareContext(ctx, `SELECT addr FROM jail WHERE expires_at > ?`)
	if err != nil {
		goto FailureClose
	}
	j.prune, err = j.db.PrepareContext(ctx, `DELETE FROM jail WHERE expires_at <= ?`)
	if err != nil {
		goto FailureClose
	}
	// Prepare statements for Add() transaction
	j.addSelect, err = j.db.PrepareContext(ctx, `SELECT expires_at FROM jail WHERE addr = ?`)
	if err != nil {
		goto FailureClose
	}
	j.addInsert, err = j.db.PrepareContext(ctx, `INSERT INTO jail (addr, blame, expires_at) VALUES (?, ?, ?)`)
	if err != nil {
		goto FailureClose
	}
	j.addUpdate, err = j.db.PrepareContext(ctx, `UPDATE jail SET blame = ?, expires_at = ? WHERE addr = ?`)
	if err != nil {
		goto FailureClose
	}

	go j.worker(workerCtx)
	return nil

FailureClose:
	j.Close()
	return err
}

func (j *SQLite3Jail) Close() error {
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
	if j.del != nil {
		err = j.del.Close()
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
	if j.addSelect != nil {
		err = errors.Join(err, j.addSelect.Close())
	}
	if j.addInsert != nil {
		err = errors.Join(err, j.addInsert.Close())
	}
	if j.addUpdate != nil {
		err = errors.Join(err, j.addUpdate.Close())
	}
	if j.db != nil {
		err = errors.Join(err, j.db.Close())
	}
	if err != nil {
		j.logger.Warn("failed to close db", "error", err)
	}
	return err
}

func (j *SQLite3Jail) Add(ctx context.Context, b *dto.BanRecord) error {
	j.shutdownMu.RLock()
	defer j.shutdownMu.RUnlock()
	if j.isShutdown {
		return ErrShutdown
	}

	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Create transaction-specific statements from prepared statements
	selectStmt := tx.StmtContext(ctx, j.addSelect)
	insertStmt := tx.StmtContext(ctx, j.addInsert)
	updateStmt := tx.StmtContext(ctx, j.addUpdate)

	// Check if record exists
	var existingExpiresAt time.Time
	err = selectStmt.QueryRowContext(ctx, b.Addr.String()).Scan(&existingExpiresAt)

	if err == sql.ErrNoRows {
		// No existing record, insert new
		_, err = insertStmt.ExecContext(ctx, b.Addr.String(), b.Blame, b.ExpiresAt)
	} else if err != nil {
		return err
	} else {
		// Record exists, only replace if longer
		if b.ExpiresAt.After(existingExpiresAt) {
			_, err = updateStmt.ExecContext(ctx, b.Blame, b.ExpiresAt, b.Addr.String())
		}
	}

	if err != nil {
		return err
	}

	return tx.Commit()
}

func (j *SQLite3Jail) Del(ctx context.Context, addr netip.Addr) error {
	j.shutdownMu.RLock()
	defer j.shutdownMu.RUnlock()
	if j.isShutdown {
		return ErrShutdown
	}
	_, err := j.del.ExecContext(ctx, addr.String())
	return err
}

func (j *SQLite3Jail) List(ctx context.Context) ([]dto.BanRecord, error) {
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

	bans := make([]dto.BanRecord, 0)
	for rows.Next() {
		var b dto.BanRecord
		var addrStr string
		if err := rows.Scan(&addrStr, &b.Blame, &b.ExpiresAt); err != nil {
			return nil, err
		}

		if addr, err := netip.ParseAddr(addrStr); err == nil {
			b.Addr = addr
		} else {
			j.logger.Warn("failed to parse ban addr", "error", err, "addr", addrStr)
			continue
		}
		bans = append(bans, b)
	}
	return bans, nil
}

func (j *SQLite3Jail) Compile(ctx context.Context) ([]dto.BanRule, error) {
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
		var addrStr string
		if err := rows.Scan(&addrStr); err != nil {
			return nil, err
		}

		addr, err := netip.ParseAddr(addrStr)
		if err != nil {
			j.logger.Warn("failed to parse ban addr", "error", err, "addr", addrStr)
			continue
		}

		// Convert address to prefix using configured prefix length
		var prefix netip.Prefix
		if addr.Is4() {
			prefixLen := j.ipv4PrefixLen
			if prefixLen <= 0 {
				prefixLen = 24
			}
			prefix = netip.PrefixFrom(addr, prefixLen)
		} else {
			prefixLen := j.ipv6PrefixLen
			if prefixLen <= 0 {
				prefixLen = 48
			}
			prefix = netip.PrefixFrom(addr, prefixLen)
		}

		if prefix.IsValid() {
			ipsb.AddPrefix(prefix)
		} else {
			j.logger.Warn("failed to create prefix from addr", "addr", addrStr)
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
func (j *SQLite3Jail) worker(ctx context.Context) {
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
