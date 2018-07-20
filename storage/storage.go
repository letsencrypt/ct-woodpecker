package storage

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Storage provides methods for interacting with a database
type Storage interface {
	AddCert(logID int64, cert *SubmittedCert) error
	GetUnseen(logID int64) ([]SubmittedCert, error)
	MarkCertSeen(id int, seen time.Time) error
	GetIndex(logID int64) (int64, error)
	UpdateIndex(logID int64, index int64) error
}

type impl struct {
	db *sql.DB
}

// New initializes a impl struct
func New(uri string) (Storage, error) {
	db, err := sql.Open("sqlite3", uri)
	if err != nil {
		return nil, err
	}
	return &impl{db: db}, nil
}

// SubmittedCert is a convience struct used to hold information relating to a submitted certificate
type SubmittedCert struct {
	ID        int
	Cert      []byte
	SCT       []byte
	Timestamp uint64
}

// AddCert adds a submitted certificate to the SubmittedCerts table
func (s *impl) AddCert(logID int64, cert *SubmittedCert) error {
	_, err := s.db.Exec("INSERT INTO SubmittedCerts (LogID, Cert, SCT, Timestamp) VALUES (?, ?, ?, ?)", logID, cert.Cert, cert.SCT, cert.Timestamp)
	if err != nil {
		return err
	}
	return nil
}

// GetUnseen returns all currently unseen certificates for a LogID
func (s *impl) GetUnseen(logID int64) ([]SubmittedCert, error) {
	rows, err := s.db.Query("SELECT ID, Cert, SCT, Timestamp FROM SubmittedCerts WHERE LogID = ? AND Seen IS NULL", logID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	var certs []SubmittedCert
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var cert SubmittedCert
		if err := rows.Scan(&cert.ID, &cert.Cert, &cert.SCT, &cert.Timestamp); err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return certs, nil
}

// MarkCertSeen updates the row once a log entry has been seen that matches the SCT
func (s *impl) MarkCertSeen(id int, seen time.Time) error {
	res, err := s.db.Exec("UPDATE SubmittedCerts SET Seen = ? WHERE ID = ?", seen, id)
	if err != nil {
		return err
	}
	if num, err := res.RowsAffected(); err != nil || num != 1 {
		if err != nil {
			return err
		}
		return fmt.Errorf("Unexpected number of rows affected, expected: 1, got: %d", res.RowsAffected)
	}
	return nil
}

// GetIndex gets the current entry index we've fetched up to
func (s *impl) GetIndex(logID int64) (int64, error) {
	rows, err := s.db.Query("SELECT LogIndex FROM LogIndexes WHERE LogID = ?", logID)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, err
	}
	var index int64
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		if err := rows.Scan(&index); err != nil {
			return 0, err
		}
		break
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	return index, nil
}

// UpdateIndex updates the entry index we've fetched up to
func (s *impl) UpdateIndex(logID int64, index int64) error {
	_, err := s.db.Exec("REPLACE INTO LogIndexes (LogID, LogIndex) VALUES (?, ?)", logID, index)
	if err != nil {
		return err
	}
	return nil
}
