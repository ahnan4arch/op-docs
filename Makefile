
install:
	cd viewer; npm install

run:
	@node viewer

build:
	if ! hash grunt 2>/dev/null; then npm install -g grunt-cli; fi
	cd viewer; grunt build

.PHONY: run build
