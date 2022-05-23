# CT Woodpecker

<p align="left">
  <img src="https://raw.githubusercontent.com/letsencrypt/ct-woodpecker/main/logo.jpg" height="200" alt="ct-woodpecker: poking holes in logs"/>
<p>

[![Build Status](https://travis-ci.org/letsencrypt/ct-woodpecker.svg?branch=master)](https://travis-ci.org/letsencrypt/ct-woodpecker)
[![Coverage Status](https://coveralls.io/repos/github/letsencrypt/ct-woodpecker/badge.svg?branch=cpu-goveralls)](https://coveralls.io/github/letsencrypt/ct-woodpecker?branch=cpu-goveralls)
[![Go Report Card](https://goreportcard.com/badge/github.com/letsencrypt/ct-woodpecker)](https://goreportcard.com/report/github.com/letsencrypt/ct-woodpecker)
[![GolangCI](https://golangci.com/badges/github.com/letsencrypt/ct-woodpecker.svg)](https://golangci.com/r/github.com/letsencrypt/ct-woodpecker)

`ct-woodpecker` pokes holes in logs and finds bugs. It is a tool for monitoring
a [Certificate Transparency][ct] log for operational problems.

Get started by [running a full example environment in Docker](#quick-start) with
one command.

---

* [About](#about)
  * [Limitations](#limitations)
* [Installation](#installation)
  * [Quick-start](#quick-start)
  * [Production Setup](#production-setup)
* [Collected Metrics](#collected-metrics)
* [Example Configuration](#example-configuration)
* [Utilities](#utilities)
* [Contributing](#contributing)
* [Photo Credit](#photo-credit)

## About

`ct-woodpecker` is designed primarily for helping log operators maintain insight
into the stability and performance of their logs. It is not a complete
stand-alone monitoring solution and is instead designed to integrate with
[Prometheus][prometheus], [Grafana][grafana], and [AlertManager][alertmanager].

`ct-woodpecker` plays some parts of both the "Monitor" role and the "Submitter"
role described in [RFC 6962 Section 5][rfc6962sec5] but is not designed to
fulfill the complete role of an independent monitor or auditor.

As a Monitor, `ct-woodpecker` fetches the current STH from a log at a regular
interval and emits Prometheus stats related to the STH age, the fetch latecy,
and any errors that occur getting the STH or validating the signature.
`ct-woodpecker` will also emit similar stats produced validating consistency
proofs between the current STH and the previous STH.

As a Submitter `ct-woodpecker` regularly issues its own test certificates using
a test CA that log operators can choose to add to their allowed roots.
`ct-woodpecker` can emit stats about latency and provides a way for log
operators to easily monitor certificate and pre-certificate submission.

After submitting test certificates `ct-woodpecker` periodically fetches new
entries from the log and emits stats about the oldest certificate it has
submitted that hasn't yet been merged into the log's merkle tree. This provides
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

The following URLs can be used to access the web interfaces of the monitoring
components:

* Prometheus web interface: `http://10.40.50.4:9090`
* AlertManager web interface: `http://10.40.50.5:9093`
* Grafana web interface (username `woodpecker`, password `woodpecker`): `http://10.40.50.6:3000`

The provided `ct-test-srv` instances offer a small API that can be used to
easily test `ct-woodpecker` and the associated monitoring in an end-to-end
setting.

For example, you can break certificate submission for `log-two` by making it
return a mock 404 response to add-chain requests:

       curl -X POST \
            -d '{"path":"/ct/v1/add-chain","code":404,"response":{"error":"oh noes!"}}' \
            localhost:4601/add-mock

Shortly afterwards (2-4m) you can expect the `CertSubmissionErrors` alert to be
firing in `http://localhost:9090/alerts` based on the `ct-woodpecker` container
being unable to submit certificates to `log-two`.

You can cause the alert to recover by removing `log-two`'s add-chain mock
by running:

       curl -X POST \
            -d '{"path":"/ct/v1/add-chain"}' \
            localhost:4601/clear-mock

The `ct-test-srv` logs also support setting mock STHs, creating inconsistent tree
views, and controlling when submitted certificates are integrated into the tree.
See the [cttestsrv management_handlers.go][cttestsrv-management-handlers] for
more information.

### Production setup

We don't recommend you use the Docker Compose environment for anything beyond
testing and development. Tailoring `ct-woodpecker` for production in your
environment is situation dependent but in general a production `ct-woodpecker`
deploy needs:

1. A production ready deployment of [Prometheus][prometheus],
   [Grafana][grafana], and [AlertManager][alertmanager].
1. A dedicated low privilege `ct-woodpecker` user.
1. An optional test issuer certificate and private key for certificate
   submission. (See the [ct-woodpecker-genissuer](#utilities) command for more).
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

## Collected Metrics

`ct-woodpecker` exports many [Prometheus][prometheus] metrics on the configured
`metricsAddr` for monitoring purposes. Below is a table of the metric name, the
type, the labels used to slice the metric, and a description.

| Metric Name      | Metric Type   | Labels              | Description                                  |
| ---------------- |---------------|---------------------|:---------------------------------------------|
| `sth_timestamp` | GaugeVec | `uri` | Timestamp of fetched STH |
| `sth_age`       | GaugeVec | `uri`            | Elapsed time since timestamp of fetched STH |
| `sth_failures`  | CounterVec | `uri` | Count of failures fetching a STH |
| `sth_fetch_total`  | CounterVec | `uri` | Count of total number of get-sth calls made against each monitored CT log |
| `sth_latency`   | HistogramVec | `uri` | Latency of fetching a STH |
| `sth_proof_latency` | HistogramVec | `uri` | Latency of fetching a STH consistency proof |
| `sth_inconsistencies` | CounterVec | `uri`, `type` | Count of instances two STHs could not be proved consistent |
| `cert_submit_latency` | HistogramVec | `uri`, `precert` | Latency from submitting a cert or precert |
| `cert_submit_results` | CounterVec | `uri`, `status`, `precert`, `duplicate` | Result from submitting a cert or precert |
| `cert_storage_failures` | CounterVec | `uri`, `type` | Count of instances a cert/SCT couldn't be saved to the local DB to watch for inclusion |
| `stored_scts` | CounterVec | `uri` | Count of unique cert/SCTs retrieved and stored in the db |
| `oldest_unincorporated_cert` | GaugeVec | `uri` |Number of seconds since the oldest cert waiting on incorporation was submitted |
| `unincorporated_certs` | GaugeVec | `uri` | Number of certs/SCTs submitted but not yet incorporated |
| `inclusion_checker_errors` | CounterVec | `uri`, `type` | Number of errors encountered attemtping to check for cert inclusion |

* Possible `sth_inconsistency` `type` values are:
  * `"equal-treesize-inequal-hash"` for when two STH's have the same treesize and different hashes.
  * `"failed-to-get-proof"` for when an error occurs fetching the consistency proof.
  * `"failed-to-verify-proof"` for when a returned STH consistency proof can't
  be validated.

* Possible `cert_submit_results` `status` values are:
  * `"fail"` for failed submissions.
  * `"ok"` for successful submissions.

* `cert_submit_results` will have a `precert="true"` label when the submission was a precert.

* `cert_submit_results` will have a `duplicate="true"` label when the submission was a resubmission of a previously submitted cert/precert.

* Possible `cert_storage_failures` `type` values are:
  * `"marshalling"` for failures to marshal a returned SCT for storage.
  * `"storing"` for failures to insert the cert/SCT into the DB.

* Possible `inclusion_checker_errors` `type` values are:
  * `"getIndex"` for failures to get the current stored tree index from the DB.
  * `"getUnseen"` for failures to find unseen certs/SCTs in the DB.
  * `"getSTH"` for failures to fetch an STH to determine entries needing to be
  fetched.
  * `"getEntries"` for failures to get entries from the log.
  * `"checkEntries"` for failures to check unseen certs against the returned new
  entries.
  * `"updateIndex"` for failures to write a new tree index to the DB.

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
    "maxGetEntries": 3000
  },
  "logs": [
    {
      "uri": "http://log-one:4600",
      "key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYggOxPnPkzKBIhTacSYoIfnSL2jPugcbUKx83vFMvk5gKAz/AGe87w20riuPwEGn229hKVbEKHFB61NIqNHC3Q==",
      "windowStart": "2000-01-01T00:00:00Z",
      "windowEnd": "2001-01-01T00:00:00Z",
      "minEntry": 10,
      "submitPreCert": false,
      "submitCert": true
    },
    {
      "uri": "http://log-two:4601",
      "key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKtnFevaXV/kB8dmhCNZHmxKVLcHX1plaAsY9LrKilhYxdmQZiu36LvAvosTsqMVqRK9a96nC8VaxAdaHUbM8EA==",
      "windowStart": "2019-01-01T00:00:00Z",
      "windowEnd": "2099-01-01T00:00:00Z",
      "minEntry": 1,
      "submitPreCert": false,
      "submitCert": true
    }
  ]
}
```

* **metricsAddr** - a bind address for the `ct-woodpecker` Prometheus metrics
  server.

* **dbURI** - a [MySQL DSN URL](https://github.com/go-sql-driver/mysql#dsn-data-source-name) specifying
  the DB username, address, and database name. _NOTE:_ The database user
  password should be provided in a separate file via the "dbPasswordFile" config
  parameter.

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

  * **maxGetEntries** - the maximum number of log entries to process each
  interval. `ct-woodpecker` will make a series of `get-entries` calls for
  entries to process until it gets `maxGetEntries` entries or reaches the tree
  head.

  * **startIndex** - an optional integer specifying the treesize to start
  checking for inclusion from. This is useful if you start `ct-woodpecker`
  monitoring against a log that already has a large tree, since it lets
  `ct-woodpecker` skip ahead to the `startIndex`.

* **logs** - an array of one or more CT logs to be configured. Each log is
  composed of a config object with the following fields:

  * **uri** - the log's URI.

  * **key** - the log's public key (PEM encoded as a single line without the PEM
  header/footer).

  * **minEntry** - log index to start inclusion checking from, for monitoring large
  pre-existing logs.

  * **windowStart** - (optional) for a sharded log the `windowStart` specifies
  the begin date for the shard's accepted validity window. `ct-woodpecker` will
  ensure the certificates it generates for this log have a `notAfter` within the
  `windowStart` and `windowEnd`

  * **windowEnd** - (optional) for a sharded log the `windowEnd` specifies
  the end date for the shard's accepted validity window. `ct-woodpecker` will
  ensure the certificates it generates for this log have a `notAfter` within the
  `windowStart` and `windowEnd`

  * **submitPreCert** - if true then precertificates for this log will be
  generated and submitted based on the global `inclusionConfig`

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
   logs. The `woodpecker` package does most of the heavy lifting for the
   `ct-woodpecker` command.
* `monitor/` - the core monitoring logic.
* `storage/` - code related to MySQL and persistent storage.
* `pki/` - general PKI utilities mostly used for test certificate issuance.
* `test/` - convenience tools for unit tests.
* `test/cttestsrv` - a purpose built in-memory mock CT log for integration
   testing.

All pull requests must be reviewed by one of the maintainers (currently [@cpu][cpu],
[@jsha][jsha], and [@roland][roland]) before merging. We expect all changes to
have robust unit tests.

## Photo credit

The `ct-woodpecker` repository logo image was provided by a [Pileated
Woodpecker][pileated] living in the Laurentides region of Quebec, Canada.
Photographed by [@cpu][cpu] March 2018.

[ct]: https://www.certificate-transparency.org
[rfc6962]: https://tools.ietf.org/html/rfc6962
[rfc6962sec5]: https://tools.ietf.org/html/rfc6962#section-5
[prometheus]: https://prometheus.io/
[grafana]: https://grafana.com/
[alertmanager]: https://prometheus.io/docs/alerting/alertmanager/
[docker]: https://docs.docker.com/install/
[docker-compose]: https://docs.docker.com/compose/install/
[pileated]: https://en.wikipedia.org/wiki/Pileated_woodpecker
[cpu]: https://github.com/cpu
[roland]: https://github.com/roland
[jsha]: https://github.com/jsha
[cttestsrv-management-handlers]: https://github.com/letsencrypt/ct-woodpecker/blob/master/test/cttestsrv/management_handlers.go
