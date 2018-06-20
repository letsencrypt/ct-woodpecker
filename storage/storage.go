package storage

import (
	"database/sql"
	"fmt"
)

// Storage provides methods for interacting with a database
type Storage struct {
	db *sql.DB
}

// New initializes a Storage struct
func New(uri string) (*Storage, error) {
	db, err := sql.Open("mysql", uri)
	if err != nil {
		return nil, err
	}
	return &Storage{db: db}, nil
}

// SCT is a convience struct used to hold information relating to an unseen SCT
type SCT struct {
	ID        int
	Raw       []byte
	Timestamp int
}

// AddSCT adds a new SCT from a certificate submission
func (s *Storage) AddSCT(logID int, sct *SCT) error {
	res, err := s.db.Exec("INSERT INTO SCTs (LogID, Raw, Timestamp) VALUES (?, ?, ?)", logID, sct.Raw, sct.Timestamp)
	if err != nil {
		return err
	}
	if res.RowsAffected() != 1 {
		return fmt.Errorf("Unexpected number of rows affected: expected 1, got %d", res.RowsAffected())
	}
	return nil
}

// GetUnseen returns all currently unseen SCTs for a LogID
func (s *Storage) GetUnseen(logID int) ([]SCT, error) {
	rows, err := s.db.Query("SELECT ID, Raw, Timestamp, Seen FROM SCTs WHERE LogID = ? AND Seen IS NOT NULL")
	if err != nil {
		return nil, err
	}
	var scts []SCT
	defer rows.Close()
	for rows.Next() {
		var sct SCT
		if err := rows.Scan(&sct.ID, &sct.Raw, &sct.Timestamp); err != nil {
			return nil, err
		}
		scts = append(scts, sct)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return scts, nil
}

// MarkSCTSeen updates the row once a entry has been seen that matches the SCT
func (s *Storage) MarkSCTSeen(id int, seen int) error {
	res, err := s.db.Exec("UPDATE SCTs SET Seen = ? WHERE ID = ?", seen, id)
	if err != nil {
		return err
	}
	if res.RowsAffected() != 1 {
		return fmt.Errorf("Unexpected number of rows affected: expected 1, got %d", res.RowsAffected())
	}
	return nil
}

// GetIndex gets the current entry index we've fetched up to
func (s *Storage) GetIndex(logID int) (int, error) {
	rows, err := s.db.Query("SELECT Index FROM LogIndexes WHERE LogID = ?", logID)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, err
	}
	var index int
	defer rows.Close()
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
func (s *Storage) UpdateIndex(logID int, index int) error {
	res, err := s.db.Exec("INSERT INTO LogIndexes (LogID, Index) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE Index = ?", logID, index, index)
	if err != nil {
		return err
	}
	if res.RowsAffected() != 1 {
		return fmt.Errorf("Unexpected number of rows affected: expected 1, got %d", res.RowsAffected())
	}
	return nil
}
