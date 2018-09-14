package storage

import (
	"database/sql"
	"fmt"
	"math/rand"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Storage provides methods for interacting with a database
type Storage interface {
	AddCert(logID int64, cert *SubmittedCert) error
	GetUnseen(logID int64) ([]SubmittedCert, error)
	GetRandSeen(logID int64) (*SubmittedCert, error)
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

// GetRandSeen returns a random certificate that has been marked seen
func (s *impl) GetRandSeen(logID int64) (*SubmittedCert, error) {
	rows, err := s.db.Query("SELECT ID FROM SubmittedCerts WHERE LogID = ? and Seen IS NOT NULL ORDER BY Timestamp ASC LIMIT 1000", logID)
	if err != nil {
		return nil, err
	}
	var ids []int
	for rows.Next() {
		var id int
		if err = rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	_ = rows.Close()

	// randomly pick an id from the list
	id := ids[rand.Intn(len(ids))]
	rows, err = s.db.Query("SELECT ID, Cert, SCT, Timestamp FROM SubmittedCerts WHERE LogID = ? and ID = ?", logID, id)
	if err != nil {
		return nil, err
	}
	var cert *SubmittedCert
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		cert = &SubmittedCert{}
		if err := rows.Scan(&cert.ID, &cert.Cert, &cert.SCT, &cert.Timestamp); err != nil {
			return nil, err
		}
	}
	return cert, nil
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
		return fmt.Errorf("Unexpected number of rows affected, expected: 1, got: %d", num)
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
	if rows.Next() {
		if err := rows.Scan(&index); err != nil {
			return 0, err
		}
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

// MalleableTestDB is a mock database client used for testing. It is exported so it can be used
// in other packages when we don't want to use an actual database for tests.
type MalleableTestDB struct {
	AddCertFunc      func(int64, *SubmittedCert) error
	GetUnseenFunc    func(int64) ([]SubmittedCert, error)
	GetRandSeenFunc  func(logID int64) (*SubmittedCert, error)
	MarkCertSeenFunc func(int, time.Time) error
	GetIndexFunc     func(int64) (int64, error)
	UpdateIndexFunc  func(int64, int64) error
}

func (s *MalleableTestDB) AddCert(logID int64, cert *SubmittedCert) error {
	return s.AddCertFunc(logID, cert)
}

func (s *MalleableTestDB) GetUnseen(logID int64) ([]SubmittedCert, error) {
	return s.GetUnseenFunc(logID)
}

func (s *MalleableTestDB) GetRandSeen(logID int64) (*SubmittedCert, error) {
	return s.GetRandSeenFunc(logID)
}

func (s *MalleableTestDB) MarkCertSeen(id int, seen time.Time) error {
	return s.MarkCertSeenFunc(id, seen)
}

func (s *MalleableTestDB) GetIndex(logID int64) (int64, error) {
	return s.GetIndexFunc(logID)
}

func (s *MalleableTestDB) UpdateIndex(logID int64, index int64) error {
	return s.UpdateIndexFunc(logID, index)
}
