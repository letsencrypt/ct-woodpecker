# Production Server Requirements

1. Systemd and Linux (tested with Ubuntu 16.04)
1. `make`
1. [Go 1.10+](https://golang.org/doc/install)

# Production Server Initial Setup

The very first time you set up a production server you will need to do a manual
install:

1. SSH to the production server as a non-root user with sudo access
1. `go get github.com/letsencrypt/ct-woodpecker/...` to clone the source code to
   your `$GOPATH`
1. `cd $GOPATH/src/github.com/letsencrypt/ct-woodpecker` to change to the source code directory
1. `sudo make install`

This will create a dedicated `woodpecker` user, install the `ct-woodpecker`
binary system-wide, populate a default config in `/etc/ct-woodpecker`, create
a bare git repo with an auto-deploy hook in `/usr/local/src/ct-woodpecker.git`,
and install, start and enable a systemd service called `ct-woodpecker`.

You may need to override the `GOCMD` and `GOPATH` defaults before calling `make
install` if you have installed Go somewhere that doesn't put the `go` command in
the `$PATH` or if your `GOPATH` isn't `~/go`. E.g.:

     `make install GOCMD=~wp/go/bin/go GOPATH=~wp/gopkg/`

If you are using a non-standard `GOCMD` or `GOPATH` be sure to also update the
`post-receive` hook in `/usr/local/src/ct-woodpecker.git/hooks/post-receive` to
set the correct values for the hook's `make install` command.

# Preparing for a Deploy

With the production server set up you can configure your development machine to
be able to push to the production server for a deploy:

     `git remote add production USERNAME@SERVER:/usr/local/src/ct-woodpecker.git`

You will need to change `USERNAME` in the above command to a non-root username
that allows you SSH access to the bare git repo.

You will need to change `SERVER` in the above command to the address/domain name
of the production server you set up in the "Production Server Initial Setup"
section.

# Doing a Deploy

From your development machine run:

     `git push production master`

If everything goes according to plan you should see the output from a successful
`make install` echoed with a `remote: ` prefix on each line as part of the `git
push` output.

The running `ct-woodpecker` instance on the prod server is restarted
automatically by the `make install` command.

You can verify the status of the `ct-woodpecker` instance by running:

* `systemctl status ct-woodpecker` to check the service state
* `journalctl -e -u ct-woodpecker` to check the `ct-woodpecker` output
