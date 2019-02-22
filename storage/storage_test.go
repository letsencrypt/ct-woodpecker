package storage

import (
	"testing"
	"time"
)

func setup(t *testing.T) Storage {
	// NOTE: We expect this DB to already be set up with a schema by
	// docker-compose.
	db, err := New("woody:dryocopus_pileatus@tcp(10.40.50.7:3306)/woodpeckerdb")
	if err != nil {
		t.Fatalf("initializing database: %s", err)
	}
	dbObj := db.(*impl)
	_, err = dbObj.db.Exec("TRUNCATE TABLE SubmittedCerts;")
	if err != nil {
		t.Fatalf("truncating SubmittedCerts: %s", err)
	}
	_, err = dbObj.db.Exec("TRUNCATE TABLE LogIndexes;")
	if err != nil {
		t.Fatalf("truncating LogIndexes: %s", err)
	}
	return db
}

func TestIndexes(t *testing.T) {
	db := setup(t)

	// GetIndex should return 0 if used with a unknown log id
	index, err := db.GetIndex(1)
	if err != nil {
		t.Fatalf("GetIndex failed: %s", err)
	}
	if index != 0 {
		t.Fatalf("GetIndex returned an unexpected index for an unknown log ID, expected: 1, got: %d", index)
	}

	// UpdateIndex should insert a new row for a unknown log id
	err = db.UpdateIndex(1, 20)
	if err != nil {
		t.Fatalf("UpdateIndex failed: %s", err)
	}
	index, err = db.GetIndex(1)
	if err != nil {
		t.Fatalf("GetIndex failed: %s", err)
	}
	if index != 20 {
		t.Fatalf("GetIndex returned an unexpected index, expected: 20, got: %d", index)
	}

	// UpdateIndex should update a row for a existing log id
	err = db.UpdateIndex(1, 30)
	if err != nil {
		t.Fatalf("UpdateIndex failed: %s", err)
	}
	index, err = db.GetIndex(1)
	if err != nil {
		t.Fatalf("GetIndex failed: %s", err)
	}
	if index != 30 {
		t.Fatalf("GetIndex returned an unexpected index, expected: 30, got: %d", index)
	}
}

func TestCerts(t *testing.T) {
	db := setup(t)

	submitted := SubmittedCert{Cert: []byte{104, 105}, SCT: []byte{116, 104, 101, 114, 101}, Timestamp: 0}
	err := db.AddCert(1, &submitted)
	if err != nil {
		t.Fatalf("AddCert failed: %s", err)
	}
	certs, err := db.GetUnseen(1)
	if err != nil {
		t.Fatalf("GetUnseen failed: %s", err)
	}
	if len(certs) != 1 {
		t.Fatalf("GetUnseen returned unexpected number of certs, expected: 1, got: %d", len(certs))
	}
	err = db.MarkCertSeen(certs[0].ID, time.Time{}.Add(time.Hour))
	if err != nil {
		t.Fatalf("MarkCertSeen failed: %s", err)
	}
	certs, err = db.GetUnseen(1)
	if err != nil {
		t.Fatalf("GetUnseen failed: %s", err)
	}
	if len(certs) != 0 {
		t.Fatalf("GetUnseen returned unexpected number of certs, expected: 0, got: %d", len(certs))
	}
	_, err = db.GetRandSeen(1)
	if err != nil {
		t.Fatalf("GetRandSeen failed: %s", err)
	}
}
