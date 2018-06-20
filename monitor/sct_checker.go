package monitor

import (
	"github.com/letsencrypt/ct-woodpecker/storage"
	"github.com/zmap/zcrypto/ct"
)

type sctChecker struct {
	client monitorCTClient
	logURI string
	db     *storage.Storage
}

func (sc *sctChecker) run() {

}

func (sc *sctChecker) checkForInclusion(scts []storage.SCT, entries []ct.LogEntry) {

}
