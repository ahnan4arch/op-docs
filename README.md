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

	make deploy

First time deploy setup for [dotCloud](http://dotcloud.com):

    sudo easy_install pip && sudo pip install dotcloud
    dotcloud setup

Initial [dotCloud](http://dotcloud.com) application setup:

    dotcloud create -f live <name>
    dotcloud push

Deployments:

  * Production: http://docs.openpeer.org/
