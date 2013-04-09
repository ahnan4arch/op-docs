Open Peer Documentation
=======================

http://docs.openpeer.org/


Editing
-------

Install documentation server dependencies:

	make install

Launch server:

	make run
	open http://localhost:8080/

Make changes and update version at top of file.

Optionally build static HTML file from markdown:

	make build

Commit and push to github.


Deployment
----------

	dotcloud push
