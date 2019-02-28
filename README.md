# CT Woodpecker

<p align="center">
  <img src="https://github.com/letsencrypt/ct-woodpecker/raw/master/logo.jpg" alt="ct-woodpecker: poking holes in logs"/>
<p>

[![Build Status](https://travis-ci.org/letsencrypt/ct-woodpecker.svg?branch=master)](https://travis-ci.org/letsencrypt/ct-woodpecker)
[![Coverage Status](https://coveralls.io/repos/github/letsencrypt/ct-woodpecker/badge.svg?branch=cpu-goveralls)](https://coveralls.io/github/letsencrypt/ct-woodpecker?branch=cpu-goveralls)
[![Go Report Card](https://goreportcard.com/badge/github.com/letsencrypt/ct-woodpecker)](https://goreportcard.com/report/github.com/letsencrypt/ct-woodpecker)

`ct-woodpecker` pokes holes in logs. It is a tool for monitoring a [Certificate
Transparency][ct] log for operational problems.

## About

`ct-woodpecker` is designed primarily for helping log operators maintain insight
into the stability and performance of their logs. It is not a complete stand
alone monitoring solution and is instead designed to integrate with
[Prometheus][prometheus], [Grafana][grafana], and [AlertManager][alertmanager].

`ct-woodpecker` plays some parts of both the "Monitor" role and the "Submitter"
role described in [RFC 6962 Section 5][rfc6962sec5]. It is not designed to
fulfill the full role of an independent monitor or auditor.

As a Monitor, `ct-woodpecker` fetches the current STH from a log at a regular
interval and emits Prometheus stats related to the STH age, the fetch latecy,
any errors that occur getting the STH or validating the signature.
`ct-woodpecker` will also emit similar stats produced validating consistency
proofs between the current STH and the previous STH.

As a Submitter `ct-woodpecker` regularly issues its own test certificates using
a test CA that log operators can choose to add to their allowed roots.
`ct-woodpecker` can emit stats about latency and provides a way for log
operators to easily monitor certificate and pre-certificate submission.

After submitting test certificates `ct-woodpecker` periodically fetches new
entries from the log and emits stats about the oldest certificate it has
submitted that hasn't yet been merdged into the log's merkle tree. This provides
log operators with a way to track and enforce their own maximum-merge-delay (MMD).

### Limitations

Remember that `ct-woodpecker` is not a complete Monitor or Auditor. Most
notably:

* `ct-woodpecker` does not fetch all entries in the monitored log's tree to
   attempt to confirm the tree made from fetched entries produces observed STH
   hashes.

* `ct-woodpecker` does not request or validate Merkle audit proofs for SCT/STH
  pairs to prove inclusion.

* `ct-woodpecker` does not verify that **any** two STHs from the same log can be
   verified by requesting a consistency proof. Presently it only verifies
   linearly observed STHs with consistency proofs.

## Installation

### Quick-start

To get started with an environment suitable for testing out `ct-woodpecker` or doing development work install [Docker][docker] and [Docker Compose][docker-compose] and then run the following command in the `ct-woodpecker` repo root:

      docker-compose up

This will create and configure:

1. A `mysql` container running MariaDB.
1. A `ct-test-srv` container running two in-memory mock CT logs (`log-one` and
   `log-two`).
1. A `ct-woodpecker` container configured to monitor `log-one` and `log-two`.
1. An `alertmanager` container running [AlertManager][alertmanager].
1. A `prometheus` container running [Prometheus][prometheus] configured to
   scrape the `ct-woodpecker` stats and use example alert rules with the
   `alertmanager` container.
1. A `grafana` container running [Grafana][grafana] configured with a data
   source for the `prometheus` container and some example `ct-woodpecker`
   dashboards.

### Production setup

We don't recommend you use the Docker Compose environment for anything beyond
testing and development. Tailoring `ct-woodpecker` for production in your
environment is situation dependent but in general a production `ct-woodpecker`
deploy needs:

1. A production ready deployment of [Prometheus][prometheus],
   [Grafana][grafana], and [AlertManager][alertmanager].
1. A dedicated low privilege `ct-woodpecker` user.
1. An optional test issuer certificate and private key for certificate
   submission. _These can be generated with the `test/ct-woodpecker-genissuer`
   command._
1. A copy of the `ct-woodpecker` binary installed somewhere in `$PATH` (e.g.
   `/usr/local/bin`).
1. A configured MariaDB database. This means a database, a database user, and
   initialized tables created using the schema from `storage/mysql/schema.sql`.
1. A configuration dir `/etc/ct-woodpecker` and config file
   `/etc/ct-woodpecker/config.json`.
1. A systemd unit to keep the `ct-woodpecker` service running and to start it at
   system boot.

An example [systemd unit](examples/ct-woodpecker.service) and [config
file](examples/config.dist.json) are provided to help you get started.

Example Prometheus alerts and Grafana dashboards are also provided in the
[examples/monitoring_and_alerting](examples/monitoring_and_alerting/) directory.

## Example Configuration

```
{
  "metricsAddr": ":1971",
  "dbURI": "woody@tcp(10.40.50.7:3306)/woodpeckerdb",
  "dbPasswordFile": "test/config/db_password",
  "fetchConfig": {
    "interval": "20s",
    "timeout": "5s"
  },
  "submitConfig": {
    "interval": "5s",
    "timeout": "5s",
    "certIssuerKeyPath": "/test/issuer.key",
    "certIssuerPath": "/test/issuer.pem"
  },
  "inclusionConfig": {
    "interval": "30s",
    "maxGetEntries": 30
  },
  "logs": [
    {
      "uri": "http://log-one:4600",
      "key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYggOxPnPkzKBIhTacSYoIfnSL2jPugcbUKx83vFMvk5gKAz/AGe87w20riuPwEGn229hKVbEKHFB61NIqNHC3Q==",
      "windowStart": "2000-01-01T00:00:00Z",
      "windowEnd": "2001-01-01T00:00:00Z",
      "maximum_merge_delay": 120,
      "submitPreCert": false,
      "submitCert": true
    },
    {
      "uri": "http://log-two:4601",
      "key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKtnFevaXV/kB8dmhCNZHmxKVLcHX1plaAsY9LrKilhYxdmQZiu36LvAvosTsqMVqRK9a96nC8VaxAdaHUbM8EA==",
      "windowStart": "2019-01-01T00:00:00Z",
      "windowEnd": "2099-01-01T00:00:00Z",
      "maximum_merge_delay": 120,
      "submitPreCert": false,
      "submitCert": true
    }
  ]
}
```

* **metricsAddr** - a bind address for the `ct-woodpecker` Prometheus metrics
  server.

* **dbURI** - a [MySQL DSN URL](https://github.com/go-sql-driver/mysql#dsn-data-source-name) specifying
  the DBusername, address, and database name. _NOTE:_ Password should be
  provided in a separate file via the "dbPasswordFile" config parameter.

* **dbPasswordFile** - a filepath for a file containing the DB user password.
  _NOTE_: File must have mode `0600`.

* **fetchConfig** - global configuration related to periodic STH fetching.

  * **interval** - a duration string describing the time period between fetching STHs

  * **timeout** - a duration string describing the timeout for fetching an STH.

* **submitConfig** - global configuration related to periodic cert issuance and
  submission. May be omitted.

  * **interval** - a duration string describing the time period between attempts
    to issue and submit certs/precerts.

  * **timeout** - a duration string describing the timeout for submitting
    a cert/precert.

  * **certIssuerKeyPath** - a filepath for a file containing a PEM encoded
  RSA/ECDSA private key corresponding to the public key in the
  **certIssuerPath** PEM encoded intermediate certificate.

  * **certIssuerPath** - a filepath for a file containing a PEM encoded x509
  certificate to use as the issuer for certificates generated for submitting
  to logs.

* **inclusionConfig** global configuration related to checking that certificates
  issued periodically by `ct-woodpecker` were included in the monitored logs.

  * **interval** - a duration string describing the time period between attempts
    to check unseen certificates for inclusion.

  * **maxGetEntries** - the maximum number of cert entries to ask a log for.
  This should be set quite high as `ct-woodpecker` will reduce the number of
  certs it asks for based on what the log will actually provide.

  * **startIndex** - an optional integer specifying the treesize to start
  checking for inclusion from. This is useful if you start `ct-woodpecker`
  monitoring against a log that already has a large tree to let `ct-woodpecker`
  skip ahead to the `startIndex`.

* **logs** - an array of one or more CT logs to be configured. Each log is
* composed of a config object with the following fields:

  * **uri** - the log's URI.

  * **key** - the log's public key (PEM encoded as a single line without the PEM
  header/footer).

  * **windowStart** - (optional) for a sharded log the `windowStart` specifies
  the begin date for the shard's accepted validity window. `ct-woodpecker` will
  ensure the certificates it generates for this log have a validity period
  within the `windowStart` and `windowEnd`

  * **windowEnd** - (optional) for a sharded log the `windowEnd` specifies
  the end date for the shard's accepted validity window. `ct-woodpecker` will
  ensure the certificates it generates for this log have a validity period
  within the `windowStart` and `windowEnd`

  * **maximum_merge_delay** - the MMD for the log.

  * **submitPreCert** - if true then poisoned precertificates for this log will
  be generated and submitted based on the global `inclusionConfig`

  * **submitCert** - if true then final certificates for this log will be
  generated and submitted based on the global `inclusionConfig`

## Utilities

`ct-woodpecker` also provides two additional utilities:

1. `ct-malformed` - a tool for generating malformed CT traffic to
   fuzz/loadtest a log.

2. `ct-woodpecker-genissuer` - a small tool for creating a one-off CA
   certificate and private key suitable for use with the `ct-woodpecker`
   `certSubmitter` config.

## Contributing

Please open an issue before starting on substantial features or code changes. We
would love to help talk through the possible design choices before putting code
to file.

Roughly the design of `ct-woodpecker` separates things into the following
package hiearchy:

* `cmd/` - individual binaries (`ct-woodpecker`, `ct-malformed`).
* `woodpecker/` - top level concerns related to monitoring all of the configured
   logs. The `woodpecker` packege does most of the heavy lifting for the
   `ct-woodpecker` command.
* `monitor/` - the core monitoring logic.
* `storage/` - code related to MySQL and persistent storage.
* `pki/` - general PKI utilities mostly used for test certificate issuance.
* `test/` - convenience tools for unit tests.
* `test/cttestsrv` - a purpose built in-memory mock CT log for integration
   testing.

All pull requests must be reviewed by one of the maintainers (currently @cpu,
@jsha, and @roland) before merging. We expect all changes to have robust
unit tests.

[ct]: https://www.certificate-transparency.org
[rfc6962]: https://tools.ietf.org/html/rfc6962
[rfc6962sec5]: https://tools.ietf.org/html/rfc6962#section-5
[prometheus]: https://prometheus.io/
[grafana]: https://grafana.com/
[alertmanager]: https://prometheus.io/docs/alerting/alertmanager/
