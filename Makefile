GOPATH ?= $(HOME)/go

BIN_DIR := $(GOPATH)/bin
INSTALL_DIR := /usr/local/bin
SERVICE_DIR := /etc/systemd/system

WOODPECKER_USER := woodpecker
WOODPECKER_HOME := /etc/ct-woodpecker
WOODPECKER_CONFIG := $(WOODPECKER_HOME)/config.json
WOODPECKER_ISSUER := $(WOODPECKER_HOME)/issuer.pem
WOODPECKER_ISSUER_KEY := $(WOODPECKER_HOME)/issuer.key

WOODPECKER_BARE_REPO := /usr/local/src/ct-woodpecker.git
WOODPECKER_UPSTREAM := https://github.com/letsencrypt/ct-woodpecker.git

WOODPECKER_CMD := $(BIN_DIR)/ct-woodpecker
WOODPECKER_DEFAULT_CONFIG := ./util/config.dist.json
WOODPECKER_DEFAULT_ISSUER := ./test/issuer.pem
WOODPECKER_DEFAULT_ISSUER_KEY := ./test/issuer.key
WOODPECKER_SERVICE := ./util/ct-woodpecker.service
WOODPECKER_POST_RECV_HOOK := ./util/post-receive.git.hook

GOCMD=go

$(WOODPECKER_HOME):
	mkdir $(WOODPECKER_HOME)

$(WOODPECKER_ISSUER): $(WOODPECKER_HOME)
	cp $(WOODPECKER_DEFAULT_ISSUER) $(WOODPECKER_ISSUER)

$(WOODPECKER_ISSUER_KEY): $(WOODPECKER_HOME)
	cp $(WOODPECKER_DEFAULT_ISSUER_KEY) $(WOODPECKER_ISSUER_KEY)
	chmod 0640 $(WOODPECKER_ISSUER_KEY)

$(WOODPECKER_CONFIG): $(WOODPECKER_HOME) $(WOODPECKER_ISSUER) $(WOODPECKER_ISSUER_KEY)
	cp $(WOODPECKER_DEFAULT_CONFIG) $(WOODPECKER_CONFIG)

$(WOODPECKER_BARE_REPO):
	git init --bare $(WOODPECKER_BARE_REPO)
	cp $(WOODPECKER_POST_RECV_HOOK) $(WOODPECKER_BARE_REPO)/hooks/post-receive
	chmod +x $(WOODPECKER_BARE_REPO)/hooks/post-receive

.PHONY: install
install: $(WOODPECKER_CONFIG) $(WOODPECKER_BARE_REPO)
	$(GOCMD) get -u ./...
	$(GOCMD) install ./...
	-systemctl stop ct-woodpecker
	cp $(WOODPECKER_CMD) $(INSTALL_DIR)
	cp $(WOODPECKER_SERVICE) $(SERVICE_DIR)
	-adduser --disabled-password --no-create-home --shell=/bin/false --gecos "" $(WOODPECKER_USER)
	chown -R $(WOODPECKER_USER):$(WOODPECKER_USER) $(WOODPECKER_HOME)
	systemctl daemon-reload
	systemctl enable ct-woodpecker
	systemctl restart ct-woodpecker
