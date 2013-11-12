Abstract
========

The holy grail of communication on the Internet has been to allow peer-to-peer communication without the requirement of any centralized servers or services.A peer-to-peer approach offers some key advantages over a centralized server approach:

  1. Greater network resilience - peers can continue to function independent of servers and can operate even if servers are down

  2. Increased privacy and security - peers communicate directly thus the data is not centralized in one location where it can be spied upon by corporations, governments, 3rd parties or hackers.

  3. Decreased cost - without the need of servers, the cost to host, administer, store and relay data is reduced substantially

  4. Scalability - a peer to peer network doesn't require servers to scale as the peers can operate amongst themselves

Unfortunately, the goal of peer-to-peer and the reality of peer-to-peer do not match. Centralization of data into the Internet cloud is prolific and firewalls frequently impede direct peer-to-peer communication making peer-to-peer connection extremely difficult to setup and challenging to architect.

What further reduces the proliferation of peer-to-peer is a lack of standardization, openness and ubiquity of the technology. The standards bodies have been working for years on firewall traversal techniques and standardization of the approaches and a new joint effort called WebRTC between the W3C and IETF on how browsers can directly communication between browsers to move media. This joint effort does not specify how signaling happens between peers so it's not a complete solutions on its own.

Performing peer-to-peer approach to signaling has been notoriously difficult for a variety of reasons:

  1. Without a publicly addressable intermediate 'server' machine to initiate communication, two peers behind firewalls are never able to communicate with each other. Thus, a peer network almost always requires some sort of rendezvous and relay servers to initiate contact between peers behind firewalls (and firewalls tend to be used more frequently than not for end users).

  2. Automatically promoting the few publicly addressable home machines into rendezvous and relay servers is not the best option. Average users tend to not want to have their home/work machines to be automatically promoted to rendezvous and relay servers since it consumes their bandwidth and costs them to relay traffic for others who "leech" off their bandwidth. This cost factor causes end users to intentionally shutdown protocols that promote end user machines into servers. Over time, the number of average users willing to have their machines operate as servers for the benefit of those leeching decreases relative to the number of those whom leech off those servers until the entire system collapses with a too great server/leech ratio. As an example, Skype's network collapsed for this very reason and they were forced to setup their own super nodes to handle the load.

  3. Some peer-to-peer networks require ports to be opened on a firewall to operate. Where possible, peers will register themselves with UPnP to open the ports when the firewall automatically. Unfortunately, many firewalls lack the ability to automatically open ports or actively disallow this feature for fear that this opens the network to security holes. If opening ports automatically is not possible then users are required to open ports manually. Thus only the technically savvy can perform this task and such peer networks tend to be limited to those who are technically savvy. This is not a universal solution since it assumes too much technical ability and responsibility of the end user.

  4. Many peer networks rely on mutual peers not behaving in an evil manner. Peers that do not act in an altruistic fashion can easily disrupt these networks. When all peers behave properly there is no problem with such a network; however, the moment an 'evil' node or cluster of 'evil' nodes is injected into the peer network, parts or all of the network can suffer fatal issues and security can be compromised.

Open Peer is peer-to-peer signaling protocol taking advantages of the IETF advances of firewall penetration techniques for moving media and adds a layer to performs the media signalling in a peer-to- peer fashion but does expect that a minimal requirement of rendezvous servers existing. Beyond the initial rendezvous to get past firewalls, the servers should drop out of the protocol flow and are no longer required.

Open Peer was designed with these main goals in mind:

  1. Openness - a protocol is freely available for anyone to implement.

  2. Greater network resilience - peers can continue to function and interoperate even if servers are down.

  3. Increased privacy and security - peers communicate directly in a secure fashion designed to protect against network ease dropping, forged communication or spying by 3rd parties or being a convenient data mining target for hackers as the information does not flow through centralized servers.

  4. Federation - the protocol makes it easy for users on one service to communicate with users on another independent service offering.

  5. Identity protection - the ability of users to easily provide proof of their identity using existing social platforms while protecting these identities from spoofed by others.

  6. Decreased cost - without the need to continuously relay signaling or media through centralized servers, the costs to host, administer, relay, replicate, process and store data on servers while providing 5 9s uptime is decreased.

  7. webRTC enabling protocol - designed to be the engine that allows webRTC to function, supporting federation of independent websites and services, provide security and online identity protection and validation, and peer-to-peer signaling bypassing the need for heavy cloud based infrastructure.

  8. Scalability - whether starting at 50 users or moving beyond 5,00,000 users, the protocol is designed to allow for easy scalability by removing the complexity of communications out of the servers.


Design Considerations
=====================

The Open Peer Protocol has several design considerations to address the realities of the Internet infrastructure while delivering the functionality required:

  * Must allow any peer to connect to any other peer (if authorized).
  * Must understand firewall principles and to offer an architecture which factors that firewalls are prevalent and within the natural scope of the architecture's basic design.
  * Must accept that it's not always desirable to have peer machines automatically promoted to rendezvous servers.
  * Must allow additional services to be layered onto of the architecture
  * Must enable peers to find each other using directory services.
  * Must enable secure peer-to-peer communication without penetration or monitoring by third parties.
  * Must allow peers to perform identity validations.
  * Must allow anonymous peers, i.e. similar to unlisted and non-guessable phone numbers.
  * Must allow for differing server rendezvous architectures, i.e. anywhere from peer-to-peer self-organized models to centralized network layouts are to be abstracted from the protocol.
  * Must not require end user signed certificates from a known authority chain for each peers on the network to establish secure communications.
  * Must not require end users or administrators to configure firewalls or open ports under normal circumstances.

Key Object Concepts
===================

### Identity

An Identity is the persona of a peer contact, be they the representation of a real person or representative entity (much like a corporation is a legal entity but not a real person). An Identity maps to a single Peer Contact although a Peer Contact can have multiple Identities.

### Asserted Identity

An Asserted Identity is an identity that can be verified through an identity service as being the legal owner of the persona rather than a fraudulent representation. In other words, a validated asserted identity can be trusted that they are whom they claim to be. Different levels of identity assertion can be claimed for any given identity starting with no provable assertion at all and moving anywhere from weak to strong verification depending on the identity validation service types available.

### Identity Lookup Server

A server that looks up and returns the Peer Contact associated with an Identity or a set of Identities and can return the public profile information for Peer Contacts.

### Identity Signing Service

A service that provides the Asserted Identities for the various personas that are owned within a particular service offering.

### Identity Provider

Any service offering that grants Identity personas, such as Facebook, LinkedIn, Twitter or other 3rd parties that offer their own Identities.

### Peer Contact

A Peer Contact is the representation of a single point of contact on the Internet regardless of the personas represented by the peer contact. A peer contact can exist at zero or more Peer Locations at any given time.

### Peer

A Peer is the single instance of a peer client application on the Internet, which registers a single Peer Contact in the Peer Domain at a particular Peer Location.

### Peer Location

A Peer Location is the representation of where a peer is located. A Peer can only exist at a single location but the Peer Contact for the Peer can register at multiple Peer Locations.

### Peer URI

A Universal Resource Identifier (URI) starting with "peer:" offering the ability to locate a specific peer resource, protocol and request type within a peer domain.

### Peer Domain

A Peer is always connected to a Peer Domain and the domain is the organization responsible for managing the connected peers.

### Peer Finder

A Peer Finder is a rendezvous server that keeps track of connected peers at their peer locations since they are connected in a dispersed fashion through a peer domain. A peer finder will utilize a database (typically distributed) to facilitation the introduction of peer communication on the same domain or across domains.

### Bootstrapper

A Bootstrapper is the introductory server where peers first go to be introduced to one (or more) Peer Finders. Peers should attempt to connect to introduced Peer Finders in order to gain entry to the Peer Domain. Once a Peer is connected to a Bootstrapped Network, the Peer should no longer require communication back to the Bootstrapper unless access to previously introduced Peer Finders are no longer accessible.

### Bootstrapped Network

A Bootstrapped Network is the representation of the entire peering network that was introduced from a Bootstrapper.

### Public Peer File

A file that contains a cryptography public key for secure conversations, information required to locate the Peer Contact within a Peer Domain, information to authorize a connection to that Peer by another Peer and public Identities associated to a peer. Any Peer without the correct Public Peer File for another Peer Contact will be unable to connect to that peer. A directory service can host and offer these Public Peer Files between peers but without this file no communication is possible between peers (thus allowing for "unlisted" peers).

### Private Peer File

A file that contains a private key to be the pair of a public key inside the Public Peer file that is used by a Peer to be used to establish secure communications between Peers. The Private Peer File is encrypted and can only be decoded with the correct key.

### Peer Pair

A file pairing consisting of both a Public Peer File and a Private Peer File.

### Provisioning Service

A service that provides account creation and account profile maintenance.

### Peer Service

Any additional services offered to peers are done through what is called a Peer Service. Examples of such services are those that perform identity assertion, TURN or future services like video conferencing mixers.


The "peer:" URI scheme
======================

Syntax
-------

`peer://<domain>/<contact-id>`

Where:

  * `<domain>` - the domain service where the Bootstrapped Network is introduced, e.g. "foo.com" or "bar.com".
  
  * `<contact-id>` - the hash result of the section A of the Public Peer File

Examples
---------

    peer://foo.com/e852191079ea08b654ccf4c2f38a162e3e84ee04
    peer://example.org/3b0056498dc7cdd6a4d5373ac0860f9738b071da
    peer://<domain>/contact-id

Syntax (future extensions)
---------------------------

`peer://foo.com/id[/<resource>][?<query>][#<fragment>][;protocol=<protocol>][;request=<request>]`

Where:

  * `<resource>` - and optional resource within the peer that is being requested.

  * `<query>` - an optional component which identifies non-hierarchical information about a resource.

  * `<protocol>` - the default value of "peer-dialog" is presumed, other extensions like "peer-http" are possible and might be presumed depending on the "lookup-type" requested

  * `<request>` - this allows control over the action required which this URI is requested, e.g. "call" might be used to establish an audio/video call to the peer or "get" might be used (or even assumed) in combination with a protocol type of "peer-http" to indicate performing an HTTP request over Open Peer.

  * `<fragment>` - an optional component which identifies direction towards a secondary resource.

Example future extensions:
--------------------------

    peer://example.org/3b0056498dc7cdd6a4d5373ac0860f9738b071da/index.php;protocol=peer-http
    peer://hookflash.com/3b00564d6a4d5373ac0860f9738b071da/;protocol=peer-http;request=get
    peer://foo.com/e852191079ea08b654ccf4c2f38a162e3e84ee04;request=call


The "identity:" URI scheme
==========================

Syntax
-------

`identity:[<type>:][//<domain>/]<identity-string>`

If a `//` is not present after the `identity:` scheme, then the identity is assumed to be a specialized registered type that must be resolved in a specialized manner. If the `//` is present then the identity is resolved by the specified domain.

Where:

  * `<domain>` - the domain service where the identity is resolved, e.g. "foo.com" or "bar.com".
  * `<type>` - the legacy type of the identity (will not include a domain in this form), e.g. "phone", "email"
  * `<identity-string>` - the string that represents the persona of the identity but the interpretation is specific to a particular domain.

The URL characters '?' ';' '#' are reserved characters in the URI scheme and should never be used within an identity.

Identities must always be written in a normalized form. Domains must always be written in lowercase and identity strings are case sensitive. For example, if the identity string "Alice" is equivalent to "alice", the identity provider must always output only one form (and the recommended is all lowercase). Without that normalization "Alice" would not be considered the same identity as "alice".

When using legacy identities, the identity is globally resolvable by any identity provider that shares a common shared global database of legacy identity types. Once a legacy identity is resolve, the domain responsible for providing service to the legacy domain can be known. Legacy identities are used for convenience to make legacy identity types that might be found in common address books into Open Peer contacts.

All legacy identity types must be written in a normalized fashion. For example, a phone number would contain the country code followed by all the dialing digits, without any unneeded dialing prefixes, spacers, or separators; or as another example, an email would be converted to all lowercase to ensure "foo@bar.com" maps to the same identity as "FOO@BAR.COM".

Examples
---------

    identity:phone:14165551212
    identity:email:foo@bar.com
    identity://foo.com/alice.78
    identity://facebook.com/id3993232
    identity://bar.com/linkedin.com/zs39923yf


The Makeup of the Public Peer File
==================================

A Public Peer File contains information required to locate, connect and establish a secure channel between peers and may contain the public identities within the same file. The Public Peer File is made up of three sections, appropriately named Section "A", Section "B" and Section "C".

Section "A" can be safely transmitted to any third party allowing any third party to know the Peer Contact's "contact ID" as well as its pubic key to prove ownership (only the owner would have the related private key).

Section "B" allows for another peer to find the peer and initiate contact to the peer. Section "B" can be withheld from any other peer when relating the peer file to another peer if the peer wishes to prove itself but does not wish be findable on the network.

Section "C" is used to include proven identities of the contact. This section can be given or withheld depending how anonymous the peer wishes to be.

The entire file is only given to third parties (i.e. Section A+B+C) when the peer is authorizing another party to establish a secure connection with the peer, find the peer on the network and release / expose information about the peer with its proven public identities. At minimal, section "A" is required to establish a secure channel between peers and Section "B" is required to allow a peer to be found by another peer and Section "C" is required to prove public identities for the peer.

A Public Peer File should contain the extension of ".peer"


Section "A" (packaged and signed by identity's private key)
-----------------------------------------------------------

  * Algorithm to use for all hash computations and encryptions related to contents of the peer file (note: this does not apply to signed JSON signatures which have their own method to describe algorithms and key selection), the default algorithm is http://meta.openpeer.org/2013/07/21/jsonmsg#rsa-sha1-aes-cfb-32-16-16-sha256-md5 (see the General Validation / Encryption Rules section).
  * Public peer file creation date
  * Public peer file expiry date
  * Salt signed by salt service's key
  * "other" custom data as desired
  * Peer's public key (in signature)

Section "B" (packaged and signed by identity's private key)
-----------------------------------------------------------

  * Peer contact's full URI (to know how to locate the peer universally but does not directly reveal any identities). Peer's contact ID part of the full peer URI is calculated as follows: hex(hash("contact:" + `<public-peer-section-A-JSON-object>`)), where the hash algorithm used is "SHA256" for the default "http://meta.openpeer.org/2013/07/21/jsonmsg#rsa-sha1-aes-cfb-32-16-16-sha256-md5" namespace. When the input `<public-peer-file-section-A-JSON-object>` is used in the hash, the same canonical algorithm method as the signature in section "A". The input into the algorithm is the entire section "A" bundle including the certificate signing the section bundle. Thus the input canonical sequence will always start start with the exact phrase (followed by the remaining information): {"sectionBundle":{"section":{"$id":"A",
  * Find secret passphrase (must be known by peer attempting to initiate a finder connection to another peer).
  * "other" custom data as desired
  * signed by public key in section "A" and referenced by peer URI


Section "C" (packaged and signed by identity's private key)
-----------------------------------------------------------

  * Peer contact's full URI (to know how to locate the peer universally). See Section "B" for calculation.
  * Any / all asserted public identities
  * "other" custom data as desired
  * signed by public key in section "A" and referenced by peer URI

The public key is used as a way to send the peer privately encrypted data from another source. As long as the other source has the correct public key it is possible to establish direct secure communication by exchanging keys using public / private keys as the encryptions method.

The salt is used in Section "A" to establish randomness into the files that cannot be forged or controllable by the creator of the file this ensuring that peer URI hashes are dispersed evenly based on combined local and remote cryptographic randomness being present.

Asserted identities are used to prove the ownership change of the peer file. These identities can also be found externally to the peer file to allow for the peer to remain anonymous unless until the peer decides otherwise.

Other customer data is arbitrary for future extension of the peer file.

The peer's contact ID and signatures in Section "B" and Section "C" are used to prove this public peer file is not two or three distinct files being glued together as a forgery.


Security Considerations
-----------------------

When verifying Section "A":

  * the salt must not be expired (or the peer file is expired)
  * the salt must be signed by the domain whose certificate is found using "Certificates Get" for the domain and the salt signing key must still be valid.
  * the Section "A" bundle must be signed by a public key whose public key value is included in the signature of the bundle

When verifying Section "B" / Section "C":

  * the domain used in the peer URI must match the domain used in the signature of the signed salt
  * the "contact ID" part of the peer URI must match the following calculation: hex(hash("contact:" + `<public-peer-section-A-JSON-object>`)), where the hash algorithm used is "SHA256" for the default "http://meta.openpeer.org/2013/07/21/jsonmsg#rsa-sha1-aes-cfb-32-16-16-sha256-md5" namespace.
  * the signature must be signed by the public key contained in Section "A"
  * the reference peer URI in the signature must be the same URI as defined within the section

The identities contained within section "C" can be verified using the standard verification methods used to validate identities (see the "Identity Validation" section).

Only elements contained within the signed sections are ever considered as part of the file. All other elements are erroneous and should be discarded or ignored and when present. In Section "A", erroneous elements outside the protection of a signature should never be used as part of the calculation of the contact ID.


Example Public Peer File
-------------------------

    {
      "peer": {
        "$version": "1",
        "sectionBundle": [
          {
            "section": {
              "$id": "A",
              "algorithm": "http://meta.openpeer.org/2013/07/21/jsonmsg#rsa-sha1-aes-cfb-32-16-16-sha256-md5",
              "created": 54593943,
              "expires": 65439343,
              "saltBundle": {
                "salt": {
                  "$id": "cf9c4688b014e13d8bdd2655912ffd3253f53768",
                  "#text": "Z3nfnDenen29291mfde...21n"
                },
                "signature": {
                  "reference": "#cf9c4688b014e13d8bdd2655912ffd3253f53768",
                  "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
                  "digestValue": "ODMxNmI3Mjd...MzIzYzk5Nzc0ZGY5MQ==",
                  "digestSigned": "DEfGM~C...0/Ez=",
                  "key": {
                    "$id": "db144bb314f8e018303bba7d52e",
                    "domain": "example.org",
                    "service": "salt"
                  }
                }
              }
            },
            "signature": {
              "reference": "#A",
              "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
              "digestValue": "OzIyMmI3NG...WJlOTY4NmJiOWQwYzkwZGYwMTI=",
              "digestSigned": "G4Fwe...0E/YT=",
              "key": { "x509Data": "MIID5jCCA0+gA...lVN" }
            }
          },
    
          {
            "section": {
              "$id": "B",
              "contact": "peer://example.com/ab43bd44390dabc329192a392bef1",
              "findSecret": "YjAwOWE2YmU4OWNlOTdkY2QxNzY1NDA5MGYy"
            },
            "signature": {
              "reference": "#B",
              "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
              "digestValue": "MWU4ODQwM2ZlOTQ...IzNDAyZTE0OWZkYg==",
              "digestSigned": "MC0...E~LE=",
              "key": { "uri": "peer://example.com/ab43bd44390dabc329192a392bef1" }
            }
          },
    
          {
            "section": {
              "$id": "C",
              "contact": "peer://example.com/ab43bd44390dabc329192a392bef1",
              "identities": {
                "identityProofBundle": [
                  {
                    "identityProof": {
                      "$id": "b5dfaf2d00ca5ef3ed1a2aa7ec23c2db",
                      "contactProofBundle": {
                        "contactProof": {
                          "$id": "2d950c960b52c32a4766a148e8a39d0527110fee",
                          "stableID": "cb4bfff3a457ed7e832b4004d7d73f0411d5c0be",
                          "contact": "peer://example.com/ab43bd44390dabc329192a392bef1",
                          "uri": "identity://facebook.com/id48483",
                          "created": 54593943,
                          "expires": 65439343
                        },
                        "signature": {
                          "reference": "#2d950c960b52c32a4766a148e8a39d0527110fee",
                          "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
                          "digestValue": "Wm1Sa...lptUT0=",
                          "digestSigned": "ZmRh...2FzZmQ=",
                          "key": { "uri": "peer://example.com/ab43bd44390dabc329192a392bef1" }
                        }
                      }
                    },
                    "signature": {
                      "reference": "#b5dfaf2d00ca5ef3ed1a2aa7ec23c2db",
                      "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
                      "digestValue": "IUe324koV5/A8Q38Gj45i4jddX=",
                      "digestSigned": "MDAwMDAwMGJ5dGVzLiBQbGVhc2UsIGQ=",
                      "key": {
                        "$id": "b7ef37...4a0d58628d3",
                        "domain": "hookflash.me",
                        "service": "identity"
                      }
                    }
                  },
                  {
                    "identityProof": {
                      "$id": "0a9b2290343734118469e36d88276ffa6277d196",
                      "contactProofBundle": {
                        "contactProof": {
                          "$id": "353c7684dcf8683540a9d9e9da00a91591864d73",
                          "stableID": "cb4bfff3a457ed7e832b4004d7d73f0411d5c0be",
                          "contact": "peer://example.com/ab43bd44390dabc329192a392bef1",
                          "uri": "identity://twitter.com/booyah",
                          "created": 54593943,
                          "expires": 65439343
                        },
                        "signature": {
                          "reference": "#353c7684dcf8683540a9d9e9da00a91591864d73",
                          "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
                          "digestValue": "TXpV...R1EzTXc9PQ==",
                          "digestSigned": "MzUz...2NGQ3Mw==",
                          "key": { "uri": "peer://example.com/ab43bd44390dabc329192a392bef1" }
                        }
                      }
                    },
                    "signature": {
                      "reference": "#0a9b2290343734118469e36d88276ffa6277d196",
                      "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
                      "digestValue": "IUe324koV5/A8Q38Gj45i4jddX=",
                      "digestSigned": "MDAwMDAwMGJ5dGVzLiBQbGVhc2UsIGQ=",
                      "key": {
                        "$id": "cb231aa9a9...eaf43f",
                        "domain": "twitter.com",
                        "service": "identity"
                      }
                    }
                  }
                ]
              }
            },
            "signature": {
              "reference": "#C",
              "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
              "digestValue": "UrXLDLBIta6sk...oV5/A8Q38GEw44=",
              "digestSigned": "MC0...E~LE=",
              "key": { "uri": "peer://example.com/ab43bd44390dabc329192a392bef1" }
            }
          }
        ]
      }
    }


The Makeup of the Private Peer File
===================================

The Private Peer File is never given out to any other peer. However, the peer file can be stored with a trusted service as the contents are encrypted (although a second level of encryption is recommended). The contents of the file must be encrypted to prevent unauthorized access to the private key that is the matching pair for the public key in the Public Peer File. This file can be used to prove ownership of the Public Peer File.

The file does not carry any recommended extension and is managed by the client application that must maintain the security and integrity of the file. A "private peer file secret passphrase" is used to protect the contents of this public peer file.

The contents of the file are as follows:


Section "A"
-----------

This section is used to prove association to the public peer file and provide a method to validate the "private peer file secret passphase" before it is used in decryption algorithms.

  * Algorithm to use for all hash computations and encryptions related to contents of the private peer file and this algorithm must match the related public peer file (note: this does not apply to signed JSON signatures which have their own method to describe algorithms and key selection), the default algorithm is http://meta.openpeer.org/2013/07/21/jsonmsg#rsa-sha1-aes-cfb-32-16-16-sha256-md5 (see the General Validation / Encryption Rules section).
  * Peer contact's full URI (see public peer file Section "B" for calculation)
  * Binary salt, encoded as: base64(`<binary-salt>`)
  * 'Private Peer File secret passphrase' proof, result = hex(hmac(`<private-peer-file-secret-passphrase>`, "proof:" + `<peer-contact-id>`))
    * note: `<peer-contact-id>` is only the contact ID part of the full peer URI whose calculation is described in Section "B" of the public peer file
    * note: the hmac algorithm uses SHA256 rather than SHA1 for the default http://meta.openpeer.org/2013/07/21/jsonmsg#rsa-sha1-aes-cfb-32-16-16-sha256-md5
  * Signed by the private key


Section "B" (encrypted using the method described in Section A)
---------------------------------------------------------------

This section contains the keying information needed as part of the private peer file.

  * Encrypted version of peer contact's full URI (to prove association), encrypted version = base64(encrypt(`<key>`, `<peer-uri>`)), where key = hmac(`<private-peer-file-secret-passphrase>`, "contact:" + base64(`<salt>`)), iv=hash("contact:" + base64(`<binary-salt>`))
  * Encrypted private key - the key is stored in "PrivateKeyInfo" unencrypted RSA encoding using PKCS #8 but then encrypted, encrypted private key = base64(encrypt(`<key>`, `<private-key>`)), where key = hmac(`<private-peer-file-secret-passphrase>`, "privatekey:" + base64(`<binary-salt>`)), iv=hash("privatekey:" + base64(`<binary-salt>`))
  * Encrypted Public Peer File - the full generated public peer file is encrypted within the private peer file; encrypted public peer file = base64(encrypt(`<key>`, `<public-peer-file>`)), where key = hmac(`<private-peer-file-secret-passphrase>`, "peer:" + base64(`<binary-salt>`)), iv=hash("peer:" + base64(`<binary-salt>`))
  * Encrypted custom private data - a JSON message of custom data can be encrypted within this section; encrypted custom JSON data =  base64(encrypt(`<key>`, `<custom-JSON-data>`)), where key = hmac(`<private-peer-file-secret-passphrase>`, "data:" + base64(`<binary-salt>`)), iv= hash("data:" + base64(`<binary-salt>`))
  * Signed by the private key

The format of the Private Peer File is defined so it can be stored on server (should a client desire to do so) with only clients that have the correct "private peer file secret passphrase" being able to request download of the file without the server knowing the value of the data contained within the file, or the actual "private peer file secret passphrase".

The Peer Contact's URI is used to indicate which Public Peer File the Private Peer File is correlated.

The key salt from Section "A" is combined with the hmac of "private peer file secret passphrase" to ensure that the "private peer file secret passphrase" is not directly used to encrypt more than one piece of data within the same file.

The "private peer file secret passphrase" proof is used so a server can verify a client does have the correct information to request download of the Private Peer File. Only a client that knows the "private peer file secret passphrase" would be able to generate the correct key proof in a derived hash challenge. The contact ID is combined with the secret to add extra complexity into the secret to ensure no two users accidentally using the same "private peer file secret passphrase" would result in the same hash in their private peer file.

The encrypted private key is the private key pair matching the public key in the Public Peer File.

The encrypted Public Peer File is a complete encryption of the Public Peer File (i.e. all sections), thus requiring only one file to store both the public and private key.

The encrypted private data is extension data for use for whatever purposes required by a client and is an encoded form of a JSON package.


Security Considerations
-----------------------

The following steps should be used to validate the private peer file:

  * The contact ID is taken from the peer URI contained in Section "A" of the private peer file, with the salt to perform the proof required to validate the "'Private Peer File secret passphrase' proof"
  * The peer URI encrypted in Section "B" is then decrypted and compared against Section "A"'s full peer URI and must match
  * The public peer file is then decrypted from Section "B" of the private and the peer URI is calculated as described in Section "B" of the public peer file and compared against the peer URI contained in Section "A" of the private peer file (and must match)
  * The signatures of the public and private peer file must be validated

Once these steps are performed, the private key in the private peer file is considered valid and may be used.

When generating a private peer file, the salt must be cryptographically random. Both sections of the private peer file must be signed to ensure the contents of the private peer file have not been modified by another entity.

All data in this file is considered strictly private; thus all data must be encrypted.

The "private peer file secret passphrase" should be a cryptographically randomly generated string rather than a user input passphrase. The generated passphrase must be sufficiently long to protect the sensitive contents it encodes.

If the private peer file secret passphrase is to be protected by a user's passphrase, the user's passphrase must undergo key stretching.


Example Private Peer File
-------------------------

    {
      "privatePeer": {
        "$version": "1",
        "sectionBundle": [
          {
            "section": {
              "$id": "A",
              "contact": "peer://example.com/ab43bd44390dabc329192a392bef1",
              "algorithm": "http://meta.openpeer.org/2013/07/21/jsonmsg#rsa-sha1-aes-cfb-32-16-16-sha256-md5",
              "salt": "YzY4NWUxMGU4M2ZjNzVkZWQzZTljYWMyNzUzZDAwNGM4NzE5Yjg1",
              "secretProof": "2ee79fea96b0c3d021aed9b26d309481cc14e492"
            },
            "signature": {
              "reference": "#A",
              "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
              "digestValue": "j6lw...x3rvEPO0vKtMup4NbeVu8nk=",
              "digestSigned": "G4Fwe...0E/YT=",
              "key": { "uri": "peer://example.com/ab43bd44390dabc329192a392bef1" }
            }
          },
          {
            "section": {
              "$id": "B",
              "encryptedContact": "cGVlcjo...NDNiZDQ0MzkwZGFiYzMyOTE5MmEzOTJiZWYx",
              "encryptedPrivateKey": "jk483n2n~3232n/34nk323j...32fsjdneen2311=",
              "encryptedPeer": "43j2332944bfdss323bjfjweke2dewbub3i...22dnnewne321~nn32n3j2/44=",
              "encryptedPrivateData": "ZGM0MzQxODBjMTgxMDY2NGQ4MWE...GUwYjMzNmI4Nzk5OWU="
            },
            "signature": {
              "reference": "#B",
              "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
              "digestValue": "UrXLDLB...Ita6skoV5/A8Q38GEw44=",
              "digestSigned": "MC0...E~LE=",
              "key": { "uri": "peer://example.com/ab43bd44390dabc329192a392bef1" }
            }
          }
        ]
      }
    }


Overall Network Architecture
============================

Network Diagram
---------------

![Network Architecture](NetworkArchitecture.png)

Network Components
------------------

Bootstrapper - a server that acts as an introductory server to the entire peer network. The Bootstrapper exclusively talks over HTTPS to clients which must have a certificate issued from a trusted certificate authority.

Salt Service - a server that generates cryptographically strong salt and signs the salt as having come from the server. This service is useful to ensure cryptographically strong random data has been correctly used whenever it is critically important and especially when a server can't trust a client will generate random data that is intentionally or accidently non-cryptographically random. The salt service exclusively talks HTTPS to clients and the certificate authority as discovered from the Bootstrapper service will sign the certificate.

Identity Service(s) - servers that provide Identity Lookup or Asserted Identities for Identities such as LinkedIn, Facebook or other 3rd party Identities. The weak form of an Asserted Identity allows a third party like Hookflash Inc. to assert an Identity is correct when the Identity Provider does not offer an Identity signing service themselves.

TURN server - a server which is used to relay information on an 'as needed' basis when the firewall is of a type where relaying is required to penetrate the firewall. The TURN service will talk the standard TURN protocol.

Finder - a server that keeps information about each Peer Contact's Peer Locations and assists Peers in establishing the initial communication between Peers. The finder may allows a few requests over HTTPS but most request must be directed over Message/RUDP/UDP or Message/SCP protocol. The requests allowed over HTTPS are specifically mentioned with each allowed request.

Conference service - this is an example service that could be utilized as a relay point when communicating between peers in a conference scenario that would typically overwhelm a standalone client's CPU or bandwidth, but no protocol has been yet defined for Open Peer.

Peer - a peer is a client that uses the various services in the architecture to help with the establishment of communication to other Peers. Once peers establish and communicate directly with other peers, they should not required to utilize server infrastructure to maintain the communication (with the exception possibly of using a TURN server). Peers use the Message/RUDP/UDP or Message/SCP protocol as their initial connection and control protocol.

Limitations to Scope of Open Peer Specification
-----------------------------------------------

Open Peer defines the communication between the client and the Open Peer services but does not delegate how the servers in the infrastructure communicate amongst each other. Open Peer does not define how peer finders are allocated amongst peers. Open Peer allows Peers to treat servers as potentially untrustworthy from a privacy perspective and thus the protocol was designed to keep sensitive information from flowing through the servers or the servers having access to the keys to decrypt the sensitive data. Open Peer does not dictate how the data contained within and between servers be secured, only that the data must be secure.


RUDP Protocol
=============

Overall Design Goals
--------------------

RUDP was designed to allow bi-direction FIFO (First-In-First-Out) congestion controlled streamed data between two peers that is modelled after TCP, except that it is highly friendly to firewalls and utilizes firewall friendly protocols and techniques to connect between peers. The RUDP can be used between peers or from server to server.

TCP is a great protocol for signaling as it is reliable and messages are always delivered in order to a report party in a FIFO manner. The major problem with TCP is that it is not firewall friendly for peer-to- peer scenarios. TCP works great for peer-to-server where one entity is not located behind a firewall (i.e. the server). However, TCP between peers using today's marketed firewalls is virtually impossible.

RUDP uses STUN/ICE/TURN as the basis for establishing peer-to-peer connections then uses a UDP packaging technique to deliver application data. Additionally because RUDP is a FIFO based protocol like TCP, it can layer protocols such as TLS directly above its transport with little to no change at all being required (other than pumping the data through an RUDP socket instead of a TCP socket).

RUDP uses ICE to perform connectivity probes between peers and utilizes a STUN extension for connecting, tear-down, and reliable as well as unreliable data acknowledgments.

RUDP supports vector based acknowledgments and XOR bit parities to prevent malicious clients from being able to pretend a download stream was downloading faster than the server is truly capable of delivering.

RUDP further supports multiple channels with a single point-to-point connection and multiple connects on a single port between multiple points. This allows for an existing connectivity probe to be reused for sending additional streams of data without performing new connectivity checks.

RUDP does not offer security beyond connectivity security offered with STUN and ICE. However, TLS or other mechanisms can be layered on top of RUDP to provide security and encryption.

RUDP is designed to be firewall friendly with minimal overhead.

Comparison to Other Protocols
-----------------------------

### DCCP / DTLS

DCCP is a good message based protocol that allows for reliable connecting and tear down and congestion control but offers a lossy data stream. DCCP was not chosen as it was desirable to have a reliable transport protocol between peers. To add security DTLS can be layered on top of DCCP.

DCCP is not readably available on all platforms (requiring a layering over UDP on major platforms like Windows. To utilize DCCP on windows would require manipulating RAW sockets and implementing the full DCCP protocol from scratch. Alternatively, DCCP would have to run on top of UDP, which is an option but adds overhead.

As such to utilize DCCP would have required a layer as:

[application level reliability layer] -> DTLS -> DCCP (optionally over UDP)

Further using DCCP would still require utilizing extension protocols to perform peer to peer firewall probing in a manner like ICE performs.

DCCP was not chosen as the lack of data reliability, overhead and work involved to support all the layers was not considered viable.

### TCP

TCP is very similar to RUDP in capabilities with one exception: the ease to penetrate firewalls between peers. TCP does not offer an ICE like mechanism to perform connectivity probes like ICE and thus was not chosen as an acceptable protocol.

### SCP

SCP is an alternative TCP like peer-to-peer communication protocol that messages can be relayed over as an alternative to RUDP protocol should the underlying framework support SCP.

### RUDP Protocol Specification

    12345678901234567890123456789012345678901234567890123456789012345678901234567890
    
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Channel Number        |          Data Length          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Flags     |      Lower 24bits of Sequence Number          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   Reserved    |             Lower 24bits of GSNR              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /                      Options and Padding                      /
    +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
    /                       Application Data                        /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    Channel Number - in the same range as allowed by TURN (0x4000 -> 0x7FFF)
    Data Length - how much application data is included in this packet after the
                  header (0 is a valid length)
    Flags - See definition below
    Lower 24bits of Sequence Number - lower 24 bits of the 64bit sequence number
    Reserved - must be set to "0" on send and ignored upon receipt
    Lower 24bits of GSNR - Lower 24bits of the 64bit GSNR (Greatest Sequence
                           Number Received). If no packets have been received this
                           should be set to the NEXT-SEQUENCE-NUMBER as received
                           from the remote party.
    Options and padding - If the EQ bit is set to zero in the flags then the
                          vector/GSNFR is included as part of the header.
    Application data - Application data at the length of the data length
    
    
    Flags are defined as follows
     0
     0 1 2 3 4 5 6 7
    +-+-+-+-+-+-+-+-+
    |P|P|X|D|E|E|A|R|
    |S|G|P|P|C|Q|R| |
    +-+-+-+-+-+-+-+-+
    PS = Parity bit of sending packet (this packet)
    PG = Parity of the Greatest Sequence Number Received (if no packets have been
         received yet then this value is "0")
    XP = XOR'd parity of all packets received up-to-and-including the GSNFR (if
         no packets have been received then this value is "0")
    DP = Duplicate packets have been received since the last ACK packet was sent.
    EC = ECN (Explicit Congestions Notification) received on incoming packet
         since last packet in sequence sent. If no packets have been received then
         this value is set to "0".
    EQ = GSNR == GSNFR (Greatest Sequence Number Received equals Greatest
         Sequence Number Fully Received). If no packets have been received then
         this value is set to "1".
    AR = ACK required (must send a STUN "RELIABLE-CHANNEL-ACK"
         indication/request or another packet with ACK information (i.e.
         header only packet without data is okay).
    R  = RFFU (Reserved For Future Use). Must be set to "0" on sending and ignored
         upon receipt
    
    
    -------------------------------------------------------------------------------
    This header is present in packet after the header if EQ flag is "0" (and
    therefor cannot be present if no packets were received from the remote party
    as the EQ value in this case must be "1").
    
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |P|Vector Length|             Lower 24bits of GSNFR             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /   [0...vector length] vector RLE information                  .
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    .            [padded RLE to next DWORD alignment (if required)] /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    P - XOR'ed parity of all packets marked as received in the vector
        (starting at the calculated XORed to-date-up-to-and-including the GSNFR)
    Vector Length - Total vector size included after header as expressed in
                    DWORDs (if the only packet missing is the GSNFR+1 then
                    vector can be zero)
    Lower 24 bits of GSNFR - The lower 24 bits of the 64bit GSNFR (Greatest
                             Sequence Number Fully Received).
    
    The entire packet including header cannot be over the PMTU or 512 bytes
    if not known.
    
    Sender will estimate the receiver's packet window. The sender will only
    send packets that are in the sequence number range from the last reported
    GSNFR up to the end of the receiver's
    estimated packet window, i.e.:
    ((sequence_number > GSNFR) &&
     (sequence_number < (GSNFR + estimated_receivers_window)).
    
    The sender will use a fairness algorithm to estimate the receiver's packet
    window and adjust the window up and down according to its own policy on how
    much data can be outstanding in the path in at half the RTT. The sender
    can verify that the receiver has in fact received packets by way of the XOR'd
    bit validation in a way that the receiver can't cheat and lie that it has
    received packets when it has not. This prevents the receiver from maliciously
    pretending it has received packets where it has not and causing the sender
    to over-estimate the capacity of the path or miscalculate RTT by the
    receiver acknowledging packets faster than it has actually received them.
    
    The sender will cryptographically randomly choose a parity bit for every
    packet is sends over the wire.
    
    The sender will include the parity bit of the packet representing the GSNR
    packet. The sender will include the XORed parity-to-date up-to-and-including
    the GSNFR packet.
    
    If the GSNFR equals the GSNR then the sender will set the EQ bit on the
    packet to 1 otherwise it will set it to 0 and include the vector/GSNFR
    additional header.
    
    If the network in which the sender receives packets is ECN aware and
    marks packets with ECN, the sender will set the EC flag on a packet to
    1 if the packet
    
    The sender will mark the last packet in a series when no more data is
    available for sending at the moment with an AR flag.
    
    The sender will automatically resend unacknowledged packets that are beyond
    haven't been acknowledged in the 2 times the total estimated
    RTT (Round Trip Time). The estimated RTT must never be lower than the
    negotiated MINIMUM-RTT.
    
    A receiver can ACK packets received in two ways:
    1) Any channel data packet sent in a series acts as an ACK for the channel
    2) Send a STUN RELIABLE-CHANNEL-ACK indication or request
    
    The receiver will ignore incoming packets with a sequence number that is
    less than the receiver's start window (the last fully ACKed packet) plus
    the receiver's window size. The receiver will ignore packets that have the
    GSNR parity incorrect for their sent packet. The receiver will close the
    connection if it receives any packets with the incorrect GP parity or the
    XP parity wrong from the same source:port:connection bound to the connection as
    this is an attempt either by a spoofer to inject data into the stream or by a
    client attempting to fake acknowledgements on packets it never received.
    
    An IP spoofer could attempt to inject data into a stream by randomly flooding
    a receiver in attempt to hit within the sequence number window but they would
    have to fake the source IP:port and channel number in order for the attack to
    succeed. Thus it is recommended that the channel number is randomly chosen
    to make a spoof flood attack less likely to succeed.
    
    Be aware that an IP spoofer may use the XP flag as an attack to attempt to
    close a connection to which they don't own by broadcasting packets but they
    are unlikely to know the correct sequence number window and channel number
    and thus would have to attempt to broadcast many packets in order to obtain
    a packet within the window. Obviously if they were sniffing and interfering
    with the network directly they could launch an attack but they already could
    interfere on a much deeper level in such situations which no protocol can stop
    but only detect. Adding security, such as TLS on top of RUDP is recommended to
    prevent faked data from being injected into a stream.
    
    The receiver will ignore packets that are outside it's own receiving window
    (i.e. from the last fully ACKed packet to the last valid received packet
    plus the receiver's window). The receiver will ignore packets beyond its
    own receiving buffer capacity (i.e. total packets beyond a missing packet
    is greater than the receiver is willing to buffer).
    
    If the AR flag was set on an accepted incoming packet for a packet
    with a sequence number greater than the last acknowledged, the sender
    will send an ACK packet immediately. The receiver can use a data packet
    for the ACK as long as it doesn't violate its own sending rules.
    
    The receiver must send an ACK packet for packets that it didn't acknowledge
    yet within the window of the oldest unacknowledged packet plus one
    calculated RTT time frame. The calculated RTT must never be lower than the
    negotiated MINIMUM-RTT.
    
    The receiver will acknowledge all packets it can every single data packet it
    sends out.
    
    The receiver will calculate the latest RTT based on the acknowledgement
    of its last packet flagged with the AR bit. The calculated RTT must never be
    set lower than the negotiated MINIMUM-RTT.
    
    With packets the receiver accepts, the receiver will look for
    acknowledgements that it can verify as accurate with the parity bits.
    Older packets containing acknowledgements where the data is still available
    to validate the parities can be used to acknowledge packets but never be
    used to mark already acknowledged packets as having not been received.
    
    Vector format is as follows:
    +--------+--------+--------+--------
    |SSLLLLLL|SSLLLLLL|SSLLLLLL|  ...
    +--------+--------+--------+--------
    
     0 1 2 3 4 5 6 7
    +-+-+-+-+-+-+-+-+
    |Sta| Run Length|
    +-+-+-+-+-+-+-+-+
    
    Sta[te] occupies the most significant two bits of each byte and can
    have one of four values, as follows:
    
    State  Meaning
    -----  -------
    0      Received
    1      Received ECN Marked
    2      Reserved
    3      Not Yet Received
    
    A "0" vector byte is used at the end of a RLE series for padding to the next
    DWORD alignment (and if interpreted would be seen as "0" packets received).
    
    NOTE: There is no guarantee that a "0" byte will be contained at the end
          of any vector RLE series as it is only used for padding.
    
    
    -----------------------------------------------------------------------------
    STUN REQUEST: RELIABLE-CHANNEL-OPEN
    
    This STUN request is used to open a channel to a remote party. In an ICE
    environment, the requester is always the ICE controlling party.
    
    Will contain following attributes:
    
    If sent over non-ICE to open an anonymous channel:
    First send request without any attributes with get 401 back with
    NONCE/REALM back.
    
    USERNAME - is set to userRandomFragRemote:userRandomFromLocal. The random frag
               should be globally unique to not cause conflict and unguessable.
    PASSWORD - is set to the userRandomFragRemote. The password is not included
               directly but instead used in the MESSAGE-INTEGRITY calculation.
               When the server issues a request it will reverse the fragments
               and use the userRandomFromLocal as the password.
    
    NONCE - as indicated by server
    REALM - as indicated by server
    
    If sent over an established ICE channel:
    USERNAME - is set to the userFragRemote:userFragLocal of the nominated ICE
               pairing (just like ICE BINDING requests).
    PASSWORD - is set to the ICE password of the remote party of the nominated
               ICE pairing (just like ICE BINDING request). The password is not
               included directly but instead used in the MESSAGE-INTEGRITY
               calculation. Short-term credential calculation is used.
    NONCE/REALM - not used.
    
    The request will always contain:
    LIFETIME - set to how long the channel should remain open before it is
               automatically closed (in seconds). Setting to zero will
               cause the channel to close immediately and there is no need to
               contain NEXT-SEQUENCE-NUMBER, MINUMIM-RTT or CONGESTION-CONTROL.
               Any data received on the channel or RELIABLE-CHANNEL-ACK will
               cause the LIFETIME attribute timeout countdown to be reset to the
               default.
    
               If not specified, a LIFETIME of 10 minutes is assumed.
    CHANNEL-NUMBER - set to the channel number the local party wishes the remote
                     party to use in all packets the remote party will send to
                     itself.
    NEXT-SEQUENCE-NUMBER - set to the first sequence number-1 that
                           will be sent from this location (the first sequence
                           number must be at least 1 but less than 2^48-1)
    MINUMIM-RTT - set to the number of milliseconds for the minimum RTT (Round Trip
                  Time). The request may contain the MINUMIM-RTT attribute to
                  indicate a minimum RTT it wishes to negotiate with the remote
                  party.
    CONGESTION-CONTROL - A list of congestion control algorithms available to use
                         by the sender with the preferred listed first. There
                         must be two of these attributes, one representing the
                         local (requester) congestion to use and one representing
                         the remote (responder) congestion algorithm.
    CONNECTION-INFO - A string representing whatever additional information is
                      required to exchange upon connection.
    
    Response will contain (signed with message integrity):
    LIFETIME - The responder can always choose a value lower than the requested
               LIFETIME of the requester but never can respond with "0" unless
               the requester sent "0". This is a negotiated value between requester
               and responder. The channel is kept alive by any channel data being
               sent or by RELIABLE-CHANNEL-ACK requests/indications. If the
               responder wishes to close the channel at a later date the responder
               can chose to issue its own CHANNEL open in the reverse direction
               with a LIFETIME of "0" with the CHANNEL-NUMBER being set to the
               CHANNEL-NUMBER the responder is currently expecting to receive
               from the remote party.
    
               If not specified, a LIFETIME of what the requester asked is assumed.
    NEXT-SEQUENCE-NUMBER - set to the first sequence number-1 that
                           will be sent from this responder (the first sequence
                           number must be at least 1 but less than 2^48-1).
    CHANNEL-NUMBER - set to the channel number the responder party wishes the
                     requester to use in all packets it will send to the
                     responder.
    MINUMIM-RTT - set to the number of milliseconds for the minimum RTT (Round Trip
                  Time) that the response party will accept. If the response
                  agrees with the minimum value by the requester it does not
                  need to include this attribute. The response may contain this
                  attribute value containing a larger than the requester if it
                  wishes to negotiate a larger minimum RTT between the two parties
                  but can never choose a shorter minimum RTT than the requester.
    CONGESTION-CONTROL - A list of congestion control algorithms available to use
                         by the receiver with the selected algorithm listed first.
                         The selected algorithm must be within the list offered
                         by the requester. If the attribute is missing then the
                         responder is assumed to use the algorithm preferred by
                         the requester. Typically, two of these attributes are
                         present in the response, one for the local (i.e.
                         responder) and one for the remote (requester).
    CONNECTION-INFO - A string representing whatever additional information is
                      required to exchange upon connection.
    
    
    When a channel is open for the first time, the responder does not start
    sending data until the requester first sends data or sends an ACK. This is
    required to ensure the response actually arrived to the requester and thus
    proving the negotiation completed.
    
    If either party responds to a renegotiation attempt (i.e. a new
    RELIABLE-CHANNEL-OPEN with changed attributes on the same channel, it must
    cease sending channel data until a data packet or ACK is received with a
    remote sequence number equal or than the sequence number in the request.
    
    If both parties attempt a simutanious renegotiation attempt a
    "487 Role Conflict" should result unless the negotiated request from the
    remote party is completely compatible with the outstanding negotiated
    request issued from the local party.
    
    If either party was attempting to close the channel but an error was
    received as a response, the channel should therefor be considered closed
    (except in the case where the NONCE is reported as stale).
    
    
    -----------------------------------------------------------------------------
    STUN REQUEST/INDICATION: RELIABLE-CHANNEL-ACK
    
    Either party can send this as a request or indication. The NONCE/REALM are
    only needed on a non-ICE situations. All other attributes must be present in
    request, except the ACK-VECTOR if it is not needed (i.e. when the only
    packet sequence number missing is the GSNR-1). If not send as an indication
    then a response is required and the response must contain the same
    attributes as listed for the request except the USERNAME, NONCE and REALM.
    
    USERNAME - same logic as RELIABLE-CHANNEL-OPEN
    PASSWORD - same logic as RELIABLE-CHANNEL-OPEN
    REALM/NONCE - same logic as RELIABLE-CHANNEL-OPEN
    CHANNEL-NUMBER - set to the channel number the local party wished the remote
                     party to use in all packets the remote party sent to
                     itself.
    NEXT-SEQUENCE-NUMBER - set to the next sequence number the requester will
                           send over the wire (but has not sent yet).
    GSNR - set to the greatest sequence number seen from the remote party.
    GSNFR - set to greatest sequence number up to which all packets have been
            received.
    RELIABLE-FLAGS - Flags indicating the parity or other useful information
    ACK-VECTOR - Vector RLE in the same fashion as in the data packet.
    
    A successful response (MESSAGE-INTEGRITY is not required) will indicate
    closure is complete. A failure response indicates the request/channel was
    not understood properly and the client should consider it closed, except
    a 483 where a packet must be re-issued to satisfy the NONCE being stale.
    
    
    -----------------------------------------------------------------------------
    STUN ATTRIBUTE: NEXT-SEQUENCE-NUMBER
    
    This is a 64bit unsigned integer attribute indicating the next sequence
    number the requester or responder expects to send (but has not sent).
    
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Next Sequence Number                     .
    .                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    
    
    -----------------------------------------------------------------------------
    STUN ATTRIBUTE: GSNR
    
    This is a 64bit unsigned integer attribute indicating the Greatest Sequence
    Number Received by the requester/responder encoded in the same method as
    the NEXT-SEQUENCE-NUMBER attribute.
    
    
    -----------------------------------------------------------------------------
    STUN ATTRIBUTE: GSNFR
    
    This is a 64bit unsigned integer attribute indicating the Greatest Sequence
    Number Fully Received by the requester/responder encoded in the same method
    as the NEXT-SEQUENCE-NUMBER attribute. In other words, all the packets
    that have been received to date up to a certain sequence number. If the GSNR
    is the same value as the GSNFR then this attribute is optional. If this
    attribute was not received on a RELIABLE-ACK then the GSNFR is assumed to
    be the same value as the GSNR.
    
    
    -----------------------------------------------------------------------------
    STUN ATTRIBUTE: MINIMUM-RTT
    
    This is a 32bit unsigned integer representing the minimum RTT in milliseconds
    negotiated by the two parties.
    
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                          Minimum-RTT                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    
    
    -----------------------------------------------------------------------------
    STUN ATTRIBUTE: CONNECTION-INFO
    
    An encoded string used at channel open to add additional information about
    the connection. The interpretation is entirely dependant on the context.
    
    
    -----------------------------------------------------------------------------
    STUN ATTRIBUTE: RELIABLE-FLAGS
    
    The reliable flags are flags needed to indicate the parity bits and other
    acknowledgement flags encoded in 4 bytes. The first byte is the only byte used
    at this time.
    
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |V|P|X|D|E|  R  | RFFU (Reserved For Future Use)                |
    |P|G|P|P|C|     | (must be set to "0" on send and ignored)      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    
    VP - XOR'ed parity of all packets marked as received in the ACK-VECTOR
         attribute (starting with the calculated XORed to-date-up-to-and
         including the GSNFR) - Same meaning as the "P" flag on the vector/GSNFR
         header in the data packet.
    PG = Parity of the Greatest Sequence Number Received
    XP = XOR'd parity of all packets received up-to-and-including the GSNFR
    DP = Duplicate packets have been received since the last ACK packet was sent.
    EC = ECN (Explicit Congestions Notification) received on incoming packet
         since last packet in sequence sent
    R  = RFFU (Reserved For Future Use). Must be set to "0" on sending and ignored
         upon receipt
    
    
    -----------------------------------------------------------------------------
    STUN ATTRIBUTE: ACK-VECTOR
    
    Has the same meaning and encoding as the optional vector encoded after the
    vector/GSNFR header. The "P" flag from the vector header is contained in the
    VP flag of the RELIABLE-FLAGS attribute.
    
    
    -----------------------------------------------------------------------------
    STUN ATTRIBUTE: CONGESTION-CONTROL
    
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |D|     RFFU    |     RFFU      | Profile preferred or selected |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    / Profile preferred or selected | Profile preferred or selected /
    +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
    / Profile preferred or selected | [Profile/padding as required] /
    +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
    
    The first byte is reserved for flags with only one flag available at this time.
    D = Direction. If "0" the congestion control list applies to the "local"
                   party. If "1" the congestion control list applies to the
                   "remote" party.
                   When receiving a request, the remote will apply to the responder
                   and the local will apply the requester. When receiving a reply
                   the remote will apply to the requester and the local will apply
                   to the responder.
    RFFU - All bits should be set to "0" and ignored upon receipt.
    
    The second byte is RFFU.
    
    This is a list of unsigned 16bit integers representing the congestions
    profile algorithms offered or accepted. The preferred or selected algorithm
    must be listed first. The order of the algorithms is assumed to be the
    preferred order of the requester or responder. The responder must select an
    algorithm within the list offered by the remote party.


Open Peer Signaling Protocol
=============================

JSON Signaling
--------------

The signaling protocol used for Open Peer is simple JSON based protocol and uses TCP, or RUDP, or DTLS/SCTP as the transport. Basically, open peer requires a reliable stream to operate.

The packaging of an JSON message for deliver to a peer entity is simple:

  * Message Size [4 bytes in network order] - The length of the raw JSON message about to be received
  * JSON data - the JSON message data to be receive of exactly the message size specified (no NUL termination is required or expected).


The packaging of an JSON message for deliver over RUDP is known as "json/stream"):

### JSON Signaling over RUDP ###

Open Peer can utilize RUDP to connection from a peer to peer. In this mode, RUDP is considered a stream and the same rules of packaging are applied depending on the context of the negotiated packaging.

The packaging of an JSON message for deliver over RUDP is known as "json/rudp"):

### JSON Signaling over TCP ###

Open Peer can utilize standard TCP to connection from a peer to a server. In this mode, TCP is considered a stream and the same rules of packaging are applied depending on the context of the negotiated packaging.

The packaging of an JSON message for deliver over RUDP is known as "json/tcp"):

### JSON Signaling Using TLS ###

Open Peer can utilize standard TLS to connection from a peer to a server. In this mode, TLS is considered a stream and the same rules of packaging are applied depending on the context of the negotiated packaging.

The packaging of an JSON message for deliver over RUDP is known as "json/tls"):

### JSON Signaling Using Web Socket Protocol ###

Open Peer can utilize standard Web Socket Protocol to connection from a peer to a server. In this mode, the web socket is considered a stream and the same rules of packaging are applied depending on the context of the negotiated packaging. For consistency, the size packaging already present in Web Sockets is ignored.

The packaging of an JSON message for deliver over RUDP is known as "json/web-socket"):

### JSON Signaling Using Secure Web Socket Protocol ###

Open Peer can utilize standard Web Socket Protocol to connection from a peer to a server. In this mode, the web socket is considered a stream and the same rules of packaging are applied depending on the context of the negotiated packaging. For consistency, the size packaging already present in Web Sockets is ignored.

The packaging of an JSON message for deliver over RUDP is known as "json/tls-web-socket"):


Message Layer Security
----------------------

Open Peer has one important expectation difference from the typical TLS scenario and thus offers an an alternative offering to TLS. Open Peer always knows the public key of the remote party in advance of issuing a connection.

TLS is majority used by HTTPS (although not exclusively) under a scenario where an anonymous client without any public / private key connects to a server that has a public / private key whose identity is validated from a trusted authority chain, such as VeriSign or Thawte. In such a situation, TLS requires negotiation to establish a bidirectional channel with known trust chains to verify the servers identity and prevent man-in-the-middle attacks without ever being able to validate the identity of the client (unless prearranged private data is exchanged additionally in the application layer).

In the Open Peer case, all peers have a public and private key, without exception, be it peer to peer or peer to server. In all cases, a peer initiating a connection always knows the public key of the designation peer in advance (thus avoiding man-in-the-middle attacks) of the connection itself. Trust is established via the Bootstrapper's introduction to services as well as Identity Providers that provide Asserted Identities.

Open Peer connections can take advantage of this situation by utilizing the pre-known public key in the initiating side to simplify the negotiation scenario and offer unidirectional encrypted streams.

The format for the unidirectional message is as follows:

  * Message Size [4 bytes in network order] - The length of the raw encrypted message, including encryption headers and integrity footers
  * Encryption key algorithm selection (16 bits network byte order, upper 8 bits reserved and must be set to "0") - When negotiating, each number represents selected keys / algorithm pair for use by the number chosen but "0" is used to represent a key / algorithm negotiation. Every "0" key causes a reset of all encryption algorithms in progress to substitute with the values specified in the "0" package. Each key / algorithm selected is selected from the supported keys / algorithms offered to the remote party, but can only be amongst the algorithms the remote party supports. As such, there is one mandated algorithm to ensure compatibility, "http://meta.openpeer.org/2012/12/14/jsonmls#aes-cfb-32-16-16-sha1-md5", where the AES (Rijndael- 128) in CFB mode with a 32 byte key size, 16 byte block size, 16 byte feedback size, SHA1-HMAC integrity protection, and an md5 hash IV sequence calculation.
  * Data bundle, consisting of:
    * integrity header of the data encrypted using the algorithm / key selected (algorithm specific)
    * JSON message encrypted using the algorithm / key selected

The advantage of pre-knowing the public key of the remote party by the sender allows for unidirectional encryption with different keys being used in each direction and allows for encryption to begin in both directions in a single round trip negotiation.

Message level security is not to be used except for this specific scenario and only when the keys are pre-known by the initiator of the connection and where both parties have public and private keys. Further, this is a message centric encryption and not stream level encryption as offered by TLS. Any received public key and asserted identities must be validated at a higher layer by exchanging identity information in correlation with public peer files.

The "0" package is sent in plain text in JSON format and the data bundle has does not contain an integrity hmac since the signature as part of the JSON package is used instead.

The "0" package contains the following:

  * Signed keying bundle including:

    * sequence number - for every "0" package, this sequence number starts at 0 and increases by 1 for each "0" package received
    * Nonce - this nonce should be validated as having only been seen once by the receiving client
    * Expiry - a time-stamp and this package must be verified as valid before the expiry or it's considered invalid
    * Context - (optional) this identifier allows the stream to correlate with other upper layers and the meaning is externally defined / negotiated
    * Encoding - the encoding technique used for this package
      * type - "pki" or "passphrase" - if "pki" then it's using public key encryption, if "passphrase" then the encoding is done with a passphrase / algorithm externally defined (typically correlated via the context)
      * fingerprint - if "pki" the fingerprint of the remote party's public key used to encrypt this data
      * algorithm - if "passphrase" is used, the algorithm to decode the keying materials
      * proof - if "passphrase" is used, this field provides proof the correct decoding key is used to decrypt the stream
    * Algorithms - preference ordered set of algorithms supported by the client; once an algorithm is marked as supported it cannot be removed from subsequent "0" package updates.
    * List of keys, with each key containing:
      * key index - this corresponds to the algorithm selection index of which key to use in any subsequent decryption
      * algorithm - the algorithm to use when decrypting payloads using this key index
      * algorithm input data - each algorithm requires its own set of keying information required for decryption, which is contained here. All sensitive data is encrypted using the public key of the remote party

For the mandatory "aes-cfb-32-16-16-sha1-md5" algorithm and encoded with "pki", the following algorithm input information is used:

  * secret - the 32 byte AES key, base64(rsa_encrypt(`<remote-public-key>`, `<32-byte-aes-key>`))
  * iv - the 16 byte AES initialization vector, base64(rsa_encrypt(`<remote-public-key>`, `<16-byte-aes-iv>`))
  * hmacIntegrityKey - the initial secret key input string, base64(rsa_encrypt(`<remote-public-key>`, `<integrity-passphrase>`))

For the mandatory "aes-cfb-32-16-16-sha1-md5" algorithm and encoded with a "passphrase", the following can be used to encode/decode the input information:

  * secret - the 32 byte AES key, hex(`<salt>`) + ":" + base64(encrypt(`<32-byte-aes-key>`)), where key = hmac(`<external-passphrase>`, "keying:" + `<nonce>`), iv = `<salt>`
  * iv - the 16 byte AES initialization vector, hex(`<salt>`) + ":" + base64(encrypt(`<16-byte-aes-iv>`)), where key = hmac(`<external-passphrase>`, "keying:" + `<nonce>`), iv = `<salt>`
  * hmacIntegrityKey - the initial secret key input string, hex(`<salt>`) + ":" + base64(encrypt(`<integrity-passphrase>`)), where key = hmac(`<external-passphrase>`, "keying:" + `<nonce>`), iv = `<salt>`

  The proof for correct keying material is calculated as follows: proof = hex(hmac(`<external-passphrase>`, "keying:" + `<nonce>`))

When the mandatory key is used, the AES CFB is initialized with these values and will continue to encrypt payloads using this keying until a new "0" package arrives. Once a new "0" package arrives all keying material is reset and forgotten and the algorithms with new keying information for subsequent messages are used for messages in a stream. The hmac is calculated using the following algorithm, hmac(`<integrity-passphrase>`, "integrity:" + hex(hash(`<decrypted-message>`)) + ":" hex(`<iv>`)). The AES key and integrity passphrase remains the same until a new "0" package is sent, but the IV is changed for every message. The next IV used for the keying selected is calculated based upon the hash of the previous IV for the selected keying and previous hmac integrity value, next_iv = hash(hex(`<previous-iv>`) + ":" + hex(`<previous-integrity-hmac>`)).

Example of the "0" package is JSON in place text with the following data in the bundle:

    {
      "keyingBundle": {
        "keying": {
          "$id": "f25f588141f7232e40b1529667b8ea626d078d20",
    
          "sequence": 0,
    
          "nonce": "11a9960ebfe2287c1e235aceb912d8d54532be05",
          "context": "8c7de9247c0c6ba629c61eed5bb1878b37b8234d:cabc3aaea9caa97a77e30a6b011c734b5cb011fd",
          "expires": "348498329",
    
          "encoding": {
            "type": "pki",
            "fingerprint": "a634858f530ada1c77d26fcd32ed75914ae863b9",
    
            "-or-": "",
    
            "type": "passphrase",
            "algorithm": "http://meta.openpeer.org/2012/12/14/jsonmls#aes-cfb-32-16-16-sha1-md5",
            "proof": "a634858f530ada1c77d26fcd32ed75914ae863b9",
          },
    
          "algorithms": {
            "algorithm": [
              "http://meta.openpeer.org/2012/12/14/jsonmls#aes-cfb-32-16-16-sha1-md5",
              "http://meta.openpeer.org/2012/12/14/jsonmls#aes-cfb-16-16-16-md5-md5"
            ]
          },
          "keys": {
            "key": [
              {
                "index": 1,
                "algorithm": "http://meta.openpeer.org/2012/12/14/jsonmls#aes-cfb-32-16-16-sha1-md5",
                "inputs": {
                  "secret": "Y21wclpXd...HFjbXgzWlhKbA==",
                  "iv": "Y21wclpXd...HFjbXgzWlhKbA==",
                  "hmacIntegrityKey": "VjFSSmVHUXlUbk5qU...aHVaV3hrYzJGRmRHbFJWREE1"
                }
              },
              {
                "index": 2,
                "algorithm": "http://meta.openpeer.org/2012/12/14/jsonmls#aes-cfb-32-16-16-sha1-md5",
                "inputs": {
                  "secret": "WTIxd2NscFhkSEZq...YlhneldsaEtiQT09",
                  "iv": "V1RJeGQyTnNjRmhrTGk...bGhuZWxkc2FFdGlRVDA5",
                  "hmacIntegrityKey": "ZmpGU1NtVkhVW...MQ=="
                }
              },
              {
                "index": 3,
                "algorithm": "http://meta.openpeer.org/2012/12/14/jsonmls#aes-cfb-16-16-16-md5-md5",
                "inputs": {
                  "secret": "Wm1wR1d4Vlltc...mtwWFVrVkZNUT09",
                  "iv": "V20xd1IxZDRWbGx...dGVnJWa1pOVVQwOQ==",
                  "hmacIntegrityKey": "VjIweGQxSXhaRFJX...WUXdPUT09"
                }
              }
            ]
          }
        },
        "signature": {
          "reference": "#f25f588141f7232e40b1529667b8ea626d078d20",
          "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
          "digestValue": "OzIyMmI3NG...WJlOTY4NmJiOWQwYzkwZGYwMTI=",
          "digestSigned": "G4Fwe...0E/YT=",
          "key": {  "x509Data": "MIID5jCCA0+gA...lVN" }
        }
      }
    }

### Security Considerations ###

Any sensitive data contained in the "0" package must be encrypted using the public key of the receiving party. Thus the key, iv, and hmacIntegrityKey must be encrypted. The entire package must be signed by the public key of the party sending the "0" package and the receiver must validate this package's signature before it assumes any of the data sent in the package is considered valid and / or trustworthy.

All keying information and salts must be generated using cryptographically random algorithms only.

The algorithms used for encrypting must be limited to the algorithms known to be supported by the remote party, but the mandatory algorithm must always be considered a valid algorithm available in any minimal implementation.

The public key used in this exchange need not be the same public key used by a higher layer, such as the public peer file's certificate.

The receiving party must verify the following:

  * The receiving party must verify the signature used in the sender's "0" package and all subsequent "0" packages.
  * The first "0" package must include the x509 certificate of the sending party (unless the receiving party is guaranteed to be able to resolve the signature key reference immediately)
  * he subsequent "0" packages must use the same signature key as the first package (thus the x509 certificate should not need to be included again)
  * A signature key reference in future "0" package signatures is used
  * The "0" package must is the first message received on the wire.
  * The algorithm presented is a known algorithm (as previously announced)

### JSON over MLS naming ###

The following names apply when signaling JSON over MLS:

  * json-mls/streams - JSON signaling using MLS over a generic stream
  * json-mls/rudp - JSON signaling using MLS over RUDP
  * json-mls/tcp - JSON signaling using MLS over TCP
  * json-mls/tls - JSON signaling using MLS over TLS
  * json-mls/web-socket - JSON signaling using MLS over web sockets
  * json-mls/tls-web-socket - JSON signaling using MLS over secure web sockets

Multiplexed Streams
-------------------

Streams can be multiplexed allowing for multiple messages that are are packaged across different channel connection numbers. In this situation each package is wrapped with a channel number where the channels numbers are negotiated at a higher layer. Each channel number represents a bi-directional connection where messages can be sent over an existing stream independent of other channels. The default channel number should start with "0" when the stream is first opened.

The format of the package is:

  * Channel number [4 bytes in network order] - The bi-directional messaging channel
  * Message Size [4 bytes in network order]
  * raw binary data

Any newly seen channel number represents the opening of a channel. A message size of "0" indicated the channel number in use is now closed.

The choice of channel number to use when creating a new channel is external to this definition.


### JSON Signaling over Multiplexed Streams ###

JSON signaling can be sent over a multiplexed stream channel.

When combining multiplexed stream packaging and JSON packaging, the format of the JSON channel is:

  * JSON data - the JSON message data to be receive of exactly the message size specified (no NUL termination is required or expected).

This allows for JSON to be efficiently packaged within the multiplexed stream where the message size is not repeated.

The following names apply when multiplexing JSON signaling over a multiplexed channel:

  * multiplexed-json/streams - JSON signaling using MLS over a generic stream
  * multiplexed-json/rudp - JSON signaling using MLS over RUDP
  * multiplexed-json/tcp - JSON signaling using MLS over TCP
  * multiplexed-json/tls - JSON signaling using MLS over TLS
  * multiplexed-json/web-socket - JSON signaling using MLS over web sockets
  * multiplexed-json/tls-web-socket - JSON signaling using MLS over secure web sockets


### Message Layer Security over Multiplexed Streams ###

Message Layer Security can be used with multiplex streams.

When combining multiplexed stream packaging and symmetric encrypted data, the format of the channel is:

  * Encryption key algorithm selection (16 bits network byte order, upper 8 bits reserved and must be set to "0") - When negotiating, each number represents selected keys / algorithm pair for use by the number chosen but "0" is used to represent a key / algorithm negotiation.
  * Data bundle, consisting of:
    * integrity header of the data encrypted using the algorithm / key selected (algorithm specific)
    * JSON message encrypted using the algorithm / key selected

The interpretation of the algorithm, data and if it contains an integrity header are negotiated externally. Algorithm numbers can be reserved for signaling purposes, so long as those algorithms are negotiated externally.

The following names apply when multiplexing JSON signaling over a multiplexed channel:

  * multiplexed-json-mls/streams - JSON signaling using MLS over a generic stream
  * multiplexed-json-mls/rudp - JSON signaling using MLS over RUDP
  * multiplexed-json-mls/tcp - JSON signaling using MLS over TCP
  * multiplexed-json-mls/tls - JSON signaling using MLS over TLS
  * multiplexed-json-mls/web-socket - JSON signaling using MLS over web sockets
  * multiplexed-json-mls/tls-web-socket - JSON signaling using MLS over secure web sockets


General Request, Notify and Result Formation Rules
==================================================

Open Peer has four types of messages:

  * request - the request types requires a "result" as a response to the request whose ID matches the request.
  * result - a result is in response to a request whose ID must match the request
  * notify - this is a special type of request whose result is ignored and not required (and no response is presumed to occur with a notify type)

All request types and results use a simplified JSON format. The messages are sent either over HTTPS/TLS/MLS/Message or over RUDP/UDP or SCP protocols. Alternative protocols are acceptable so long as they maintain the integrity and public / private key aspects of these protocols.

Every request must include the federated domain which the request is being processed and the application ID associated with the request (the result should use the application ID of the original request). Every request type must include an ID and a handler service and method being invoked (to assist with message handling, processing and routing). The ID must be cryptographically strong and random thus checks to see which data channel the response comes on is not required. Every result message must mirror the request type's ID and include a time-stamp to assist with detecting network time problems (whereas the timestamp is optional on request types).

Even though all requests / responses are written in human readable form in this document, on-the-wire requests and responses should be written for favor of size efficiency. The recommended method is the Open Peer canonical form using the algorithm for the canonicalization of JSON signatures as specified in this document. This ensures the wire format is optimal on the wire since the canonical form is fairly compact (although if a compression algorithm is applied to the message at a higher layer then the wire savings might become moot).

The client may receive an error complaining that a request has expired if the client's clock was set wrong (401). Hence in every result, the epoch of the server will be sent for the client to detect potential clock errors. To reduce issues, the client should use a secure NTP service to set its own clock at some point before initiating contact to a server or another peer.

The client is responsible for disconnecting at all times from the server. In the case of peer to peer, the initiating peer is considered the client role and the receiving peer plays the server role.

There are exceptions to this rule. The server will close a connection without warning based on two inactivity time-outs. The larger timeout is based upon an expiry window when the entity is known or "registered" to the server. The smaller timeout window of inactivity (chosen and unspecified at the discretion of the server) is based on not having received any request or notification on a channel within that defined timeframe. If either of those two timeouts occurs, the server may disconnect which is typically the responsibility of the client. The server may disconnect any client it sees as likely malicious behavior.

If a client disconnects without sending the unregister request, the server should assume the client disconnected prematurely and will discard any associated sessions.

Other disconnection rules are specified whenever they are exceptions to the rule or the exceptions.


Browser Considerations
----------------------

When making requests from a browser it is typical for these to be cross-origin. The browser enforces security policies when making cross-origin requests that limit which server may be called for certain types of requests. The W3C [Cross-Origin Resource Sharing](http://www.w3.org/TR/cors/) specification implemented by modern browsers can be used to configure these policies.

For a server to support Open Peer cross-origin requests it must:

  * Respond to HTTP `OPTIONS` requests with the following headers (empty body):

        Access-Control-Allow-Origin: *
        Access-Control-Allow-Headers: Content-Type
        Access-Control-Allow-Methods: POST, GET, OPTIONS

  * Respond to `POST` requests with the following header:

        Access-Control-Allow-Credentials: true
        Access-Control-Allow-Origin: *


General Validation / Encryption Rules
-------------------------------------

The default algorithm used for messaging security attributes is namespaced as:
http://meta.openpeer.org/2013/07/21/jsonmsg#rsa-sha1-aes-cfb-32-16-16-sha256-md5

This algorithm does not have to be written into each JSON message and is the mandatory supported algorithm to support.

This algorithm breaks down as follows:

  * RSA compatible public / private keys - public key format = X.509 DER encoding (BER decoding), private key format = "SubjectPublicKeyInfo" PKCS #1
  * SHA1 validation hashes / hmacs
  * AES encryption (Rijndael 128)
  * AES CFB mode
  * 32 byte keys
  * 16 byte block size
  * 16 byte feedback size
  * SHA256 AES key hash / hmac calculation (where applicable)
  * MD5 AES IV hash / hmac calculations (where applicable)


Open Peer uses the following definitions (unless otherwise specified):

  * public key - a RSA compatible public key encoded as X.509 DER encoding (BER decoding) format
  * private key - a RSA compatible encoded as "SubjectPublicKeyInfo" PKCS #1 format.
  * signature key - a key defined or referenced from within a signature (see JSON Signatures).
  * key - a binary value key or passphrase used as input into encrypt / decrypt routines which may pre-pass through hash / hmac algorithms before being utilized.
  * IV - the initialization vector for an encryption / decryption algorithm, always 16 bytes long.
  * passphrase - a cryptographically generated string using limited subset of the visible ASCII characters, or a user input passphrase. Each character in a passphrase is given a security strength of 5 bits. Thus a passphrase input into a "SHA1" algorithm should contain a minimal "(20 x 8) / 5 = 32" characters; a passhrase used for AES should contain a minimal "(32 x 8) / 5 = 52" characters; a passphrase used for IV calculation should contain a minimal "(16 x 8) / 5 = 26" characters;
  * salt - binary cryptographically random data
  * salt string - passphrase compatible cryptographically random data


Open Peer uses the following definitions for use with the "http://meta.openpeer.org/2013/07/21/jsonmsg#rsa-sha1-aes-cfb-32-16-16-sha256-md5" algorithms (unless otherwise specified):

  * hash(...) - the input can be binary, a passphrase, or a string when used for validation purposes. The algorithm used is "SHA1" for validation [output 20 bytes binary], "SHA256" when used as input for encrypt(...) / decrypt(...) [outputs 32 bytes binary], and "MD5" when used for IV calculation [outputs 16 bytes binary].
  * hmac(key, value) - the key can be binary, a passphrase, or a string depending on the input context of the key's input value or calculated value. The hmac algorithm used is "SHA1" for validation [output 20 bytes binary], "SHA256" when used as input for encrypt(...) / decrypt(...) [outputs 32 bytes binary], and "MD5" when used for IV calculation [outputs 16 bytes binary].
  * encrypt(...) - a key used for encryption / decryption using AES Rijndael 128 algorithm in CFB mode with a key size always set to 32 bytes, and IV of 16 bytes, 16 byte block size and a feedback size of 16 bytes (default for OpenSSL / CryptoPP). Care must be taken to never encrypt two different pieces of information with the same key and IV as this exposes a technique that can be exploited to calculate the original secret encryption key.
  * encrypt(hash(...)) - Same algorithm as encrypt(...) but the hash uses "SHA256" instead of "SHA1".
  * encrypt(hmac(...)) - Same algorithm as encrypt(...) but the hash uses hmac with "SHA256" instead of "SHA1".
  * decrypt(hash(...)) - Same algorithm as encrypt(...) but the hash uses "SHA256" instead of "SHA1".
  * decrypt(hmac(...)) - Same algorithm as encrypt(...) but the hash uses hmac with "SHA256" instead of "SHA1".
  * base64(...) - Coverts from raw binary input to base 64 encoding. This is the default encoding for binary values of variable or long length. All base64 encoding / decoding routines must use standard RFC4648 encoding, without line separators, and with "=" byte padding mandated strictly. This ensures a canonical form of base 64 is used in input hash calculations.
  * decode64(...) - Converts from a base 64 encoded string to raw binary
  * hex(...) - Converts from binary to a hex encoded string [always lowercase hex]
  * bin(...) - Converts from a hex encoded string to binary
  * sign(key, value) - Using the private key specified, sign the value, returns a binary result. Care must be taken when using sign to never sign directly information given from an untrusted party. If untrusted data must be signed, the signature must always use a computed hashed version of the untrusted data. The signer should use a "Signature Scheme with Appendix (SSA)".
  * verify(key, value) - Using the public key specified, verify the binary value which was the result of a previous signature. The verifier should use a "Signature Scheme with Appendix (SSA)".
  * rsa_encrypt(key, value) - Using either the public or private key specified, encrypt the data. The algorithm should use "Optimal Asymmetric Encryption Padding (OAEP)" used with a SHA1 hash being used.
  * rsa_decrypt(key, value) - Using either the public or private key specified, decrypt the data. The algorithm should use "Optimal Asymmetric Encryption Padding (OAEP)" used with a SHA1 hash being used.
  * key_stretch(...) - takes a user inputted string and applies a repetitive hash in a loop to strengthen the key not by adding cryptographic bits of security but to ensure that brute force attacks on the value take a minimum amount of CPU time to compute the attack value. User input values should always be combined with unique salt to ensure the same two inputted values do not result in the same result (to prevent hash table lookup results on user values). For more on key stretching, see http://en.wikipedia.org/wiki/Key_stretching


JSON Signatures
---------------

### Algorithm ###

Open Peer JSON signatures are used to verify signatures within the JSON. The signatures contain a data part, a signature part and a bundle to encapsulate the two parts together.

The signature output typically looks something like this:

    {
      dataBundle {
        "data" : {
          "$id": "4bf7fff50ef9bb07428af6294ae41434da175538"
        },
        "signature": {
          "reference": "#4bf7fff50ef9bb07428af6294ae41434da175538",
          "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
          "digestValue": "jeirjLr...ta6skoV5/A8Q38Gj4j323=",
          "digestSigned": "DE...fGM~C0/Ez=",
          "key": {
            "$id": "9bdd14dda3f...dd174b5d5bd2",
            "domain": "example.org",
            "service": "finder"
          }
        }
      }

The signature contains a unique reference ID to the data that is signed, which establishes a clear relation to the signed JSON object. The algorithm is specified for compatibility, and must be used in preference to the default algorithms in use inside the message where signature is present. This ensures the signature can be copied from message to message while retaining validation.

The digest value is calculated as follows: digest = hash(canonical(`<data-object>`))
The digest value is output into JSON as follows: base64(`<digest>`)

The canonical form of JSON is always used to ensure the output written on the wire is always reassembled with exact ordering, white spacing rules, and escape sequence rules. This ensures maximum compatibility. The JSON object being signed must be rendered to a string as if it were a standalone rendered JSON object where the final message is in the format: {"name":{...}}

The digest signed is calculated as follows: digestSigned = base64(privateKeySign(`<digest>`))

When verifying this algorithm's signature the digest value is recalculated using the following: verficationDigest = hash(canonical(`<data-object>`))

The binary verification digest has value is compared against the decode64(`<signature-digest-value>`) and must be byte-for-byte equal.

The key used to verify the signature comes from they "key" specified in the signature. This key can be the full public key or a descriptive reference to which public key was used.

The signature verification is as follows: verify(`<referenced-public-key>`, decode64(`<digest-signed>`))


### Signature Key containing x509 Public Key ###

This form of signature contains the full X.509 DER encoding (BER decoding) format encoded as base 64 in the signature and thus does not need to be externally referenced or resolved.

An example:

    "signature": {
      "reference": "#4bf7fff50ef9bb07428af6294ae41434da175538",
      "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
      "digestValue": "jeirjLr...ta6skoV5/A8Q38Gj4j323=",
      "digestSigned": "DE...fGM~C0/Ez=",
      "key": { "x509Data": "MIIDCCA0+gA...lVN" }
    }


### Signature Key Referenced from Certificates Get ###

This form of signature contains a reference to a domain where the "Certificates Get" can be used to obtain the set of keys used within the signature. The "$id" in the key maps to the ID representing the certificate and the "service" maps to the service whose signature was used to create the signature.

An example:

    "signature": {
      "reference": "#4bf7fff50ef9bb07428af6294ae41434da175538",
      "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
      "digestValue": "jeirjLr...ta6skoV5/A8Q38Gj4j323=",
      "digestSigned": "DE...fGM~C0/Ez=",
      "key": {
        "$id": "9bdd14dda3f...dd174b5d5bd2",
        "domain": "example.org",
        "service": "finder"
      }
    }


### Signature Key Referenced from Peer URI ###

This form of signature references the peer URI for the public peer file file that can be used to verify the signature. The public peer file (section "A") must be available to verify this form of signature.

An example:

    "signature": {
      "reference": "#4bf7fff50ef9bb07428af6294ae41434da175538",
      "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
      "digestValue": "jeirjLr...ta6skoV5/A8Q38Gj4j323=",
      "digestSigned": "DE...fGM~C0/Ez=",
      "key": { "uri": "peer://example.com/ab43bd44390dabc329192a392bef1" }
    }


### Signature Key Referenced by Fingerprint ###

This form of signature references the hash fingerprint of the raw public key (i.e. not base64 encoded) that can be used to verify the signature. This is used in situations where the public key is expected to be known in advanced and thus is a method to ensure the signature was generated from that expected public key. The fingerprint is calculated using: fingerprint = hex(hash(`<public-key>`))

An example:

    "signature": {
      "reference": "#4bf7fff50ef9bb07428af6294ae41434da175538",
      "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
      "digestValue": "jeirjLr...ta6skoV5/A8Q38Gj4j323=",
      "digestSigned": "DE...fGM~C0/Ez=",
      "key": { "fingerprint": "1dcc8f8bd79e214f0eb7fc6c9fb8df0812171ca3" }
    }


Identity Validation
-------------------

An identity proof bundle contains information required to protect a peer URI from being fraudulently associated to an identity, and an identity from becoming fraudulently associated to a peer URI.

The first step in identity protection is for the peer URI to assert itself as the identity and then for an identity provider to validate the assertion by signing the assertion given by the peer URI.

An example identity proof bundle:

    "identityProofBundle": {
      "identityProof": {
        "$id": "b5dfaf2d00ca5ef3ed1a2aa7ec23c2db",
        "contactProofBundle": {
          "contactProof": {
            "$id": "2d950c960b52c32a4766a148e8a39d0527110fee",
            "stableID": "123456",
            "contact": "peer://example.com/ab43bd44390dabc329192a392bef1",
            "uri": "identity://domain.com/alice",
            "created": 54593943,
            "expires": 65439343
          },
          "signature": {
            "reference": "#2d950c960b52c32a4766a148e8a39d0527110fee",
            "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
            "digestValue": "Wm1Sa...lptUT0=",
            "digestSigned": "ZmRh...2FzZmQ=",
            "key": { "uri": "peer://example.com/ab43bd44390dabc329192a392bef1" }
          }
        }
      },
      "signature": {
        "reference": "#b5dfaf2d00ca5ef3ed1a2aa7ec23c2db",
        "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
        "digestValue": "IUe324koV5/A8Q38Gj45i4jddX=",
        "digestSigned": "MDAwMDAwMGJ5dGVzLiBQbGVhc2UsIGQ=",
        "key": {
          "$id": "b7ef37...4a0d58628d3",
          "domain": "domain.com",
          "service": "identity"
        }
      }
    }

The identity URI being validated is contained within the "contactProof" JSON object.

The following steps must be perform to prove an identity is associated with a peer URI:

  * the current date time-stamp (within the "contactProof") must be beyond the creation date (a small window is allowed for small clock variations)
  * the current date time-stamp (within the "contactProof") must not be beyond the expiry date
  * peer URI (within the "contactProof") must match the peer URI being associated
  * the signature on the "contactProof" must be signed by the public key from the public peer file associated with the peer URI
  * the signature on the "identityProof" must be signed by the domain from the identity URI being validated and the referenced certificate obtained and checked from performing a "Certificated Get" on the domain; alternatively if the identity URI is of a legacy type, an identity lookup must be performed on the identity and provider of the identity returned by by the lookup must match the domain referenced in the signature

An identity lookup should be performed on the identity to obtain the latest identity proof thus only the latest identity proof should be considered valid.


Open Peer Mandated Signature Algorithm
--------------------------------------

This is the default mandated algorithm that must be supported by all implementations to allow for JSON signatures:
http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1

This is a namespace URL only and not a URI reference to a valid document definition. If the signature algorithm is omitted this algorithm must be applied, but all clients should always output their signature algorithm as part of the signature.

The hash algorithm used is SHA1. The signature public key / private keys are RSA compatible.

This algorithms uses the canonical form whose rules are described in the next sub-section.


### Canonical JSON ###

The canonical form of JSON is always used to ensure the output written on the wire is always reassembled with exact ordering, white spacing rules, and escape sequence rules. This ensures maximum compatibility. The JSON object being signed must be rendered to a string as if it were a standalone rendered JSON object where the final message is in the format: {"name":{...}}

The canonical rules as described below are for this algorithm:
http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1

If the rendered object doesn't have a string part in the JSON lexical string:value pairing (as it's a value- only) then the object name is based upon the parent array's/object string in its string:value pair (or the parent's parent as need be). This canonical rendered string requires absolutely no white space between tokens. All strings must be in normalized to UTF-8 format with only these escape sequences used: \" \\ \f \n \r \b

Unicode escape sequences are converted to UTF-8 format. Number sequences must not have unnecessary leading or trailing zeros. Numbers are rendered "as is", i.e. in the format they are put inside the original JSON package where the signature is applied.

Any object's string:value pairing that begin with "$" in the string part are placed in the order they appear in the JSON package where the signature is applied before any other string:value pairs inside the object. Next any object containing a string:value pair who's lexical string name is "#text" is placed after those strings starting with "$". Finally, all remaining string:value pairs follow in the order they appear in the JSON package where the signature is applied.

The "$", "#text" and 'other' ordering is used to ensure the implementations which wish to process the JSON in XML form can still render back/forth from XML to JSON and still be capable of generating signatures properly. The "$" prefix was chosen specifically because it is a non special variable name in JavaScript where JSON has been most prominently adopted but yet still denotes a special character for the sake of JSON/XML conversions.

JSON objects that have member string:value pairs that start with "$" in their string parts are only allowed to contain string, number, true, false or null values. JSON objects that have a member string:value pair with the string part equal to "#text" can only have a string as the corresponding value. This restriction is put into Open Peer to allow for easy JSON/XML conversions.


General Result Error Code Reasons
=================================

Error replies appear as follows:

    {
      "result": {
        "$handler": "handler",
        "$method": "method",
        "$timestamp": 439439493,
        "$id": "abc123",
    
        "error": {
          "$id": 404,
          "#text": "Not Found"
        }
      }
    }


The reasons codes closely match the HTTP error code specification for familiarity. Error results may contain additional information depending on the error and requirements of the error result.

### 301 - Moved Permanently

The requested Peer Contact has changed and is now registering itself under a new Peer Contact. The client's response should be to resolve again the Identity that pointed to the original Peer Contact in an attempt to locate the new Peer Contact.

### 400 - Bad Request

The method in the request is not valid.

### 401 - Unauthorized

One of the security checks has failed to pass in the request. The server may issue information on what exactly failed to authorize to assist debugging the issue.

### 403 - Forbidden

The data specified is invalid and fixing any security check issues will not fix the situation. The server may issue information on what exactly was the issue with the data to assist debugging the issue.

### 404 - Not Found

This error is returned if the requested Peer Contact, session or other resource is not found. This error is also returned from any request where the session or Peer Contact was valid but is no longer valid, e.g. situations where requests have been made to sessions which have already been unregistered yet unknown to the connected client due to the nature of asynchronous eventing.

A 404 error does not mean the resource never existed or will not exist in the future. The contact may not be registered at this time and that would cause a 404 error even though in the past it may have been registered.

### 409 - Conflict

A conflict has occurred, such as an edit conflict with version numbers.

### 426 - Upgrade Required

A client has requested a method that is not accessible since an upgrade is required. This will be sent if a client's certificates have expired and attempt to access a method or may be sent if a client is using an out-dated request.

### 480 - Temporarily Unavailable

The request may optionally include an expiry when the request can be tried again.


Bootstrapper Service Requests
=============================

The communication to the Bootstrapper is done over HTTPS POST requests exclusively whose HTTPS server certificate was signed by one of the trusted root Internet certification authorities. For security purposes, the Bootstrapper is the introducer to all other services within the network including appropriate security credentials to connect to each network component.

Locating the Bootstrapper
------------------------

### Overview

The Bootstrapper is the introductory service into the domain responsible for a Peer Contact and DNS is used to locate the Bootstrapper.

A peer contact is written in the following form:
peer://domain.com/e433a6f9793567217787e33950211453582cadff

And an identity is written in the following form:
identity://domain.com/alice

In both cases, an HTTPS POST request is this performed on "domain.com", using the following URL:
https://domain.com/.well-known/openpeer-services-get

Clients must confirm the HTTPS certificates comes from the same domain as the original domain request and reject any records that do not.


Services Get Request
--------------------

### Purpose

This request is required to obtain a list of services available on the peer network as well as establish a hierarchy of certificate trust.

### Inputs

None.

### Returns

  * Service ID
  * Service Type
  * API Version
  * URI - (optional) - if the service is based on a single URI then this is returned, otherwise individual methods are specified and each service type will determine if a single URI is needed versus listing individual methods involved.
  * List of requests methods, which includes
    * Method name
    * URI
    * Other request specific information
  * Public key information - (optional) used when protocol used is not based on a root certificate authority

### Security Considerations

The client must ensure the server has an HTTPS certificate that was issued by a root certificate authority and that the certificate offered by the server is still within the X.509 validity date. The certificate authority for some Bootstrapped Networks may be pre-built into a client application and verified as accurate and can respond to mismatch as deemed appropriate by the client. The client may issue more than one certificate per service should an overlap window of X.509 certificate validity be required.  

The server does not need to know or verify a client's intentions.  

A 302-redirect error response can be returned by this response to allow the request to be redirected to another server. This allows this service to be easily hosted as needed.  

The request nor the response should have an ID associated with the request / response and does not need to include an time-stamp. This is the only request in the system that has this exception. This allows for a hard-coded file to be uploaded on a server as the response to any request on the system to allow for easy service delegation without installing any server side scripting.

### Example

    {
      "request": {
        "$domain": "example.com",
        "$appid": "xyz123",
        "$id": "abc123",
        "$handler": "bootstrapper",
        "$method": "services-get"
      }
    }
.

    {
      "result": {
        "$domain": "example.com",
        "$appid": "xyz123",
        "$id": "abc123",
        "$handler": "bootstrapper",
        "$method": "services-get",
        "$timestamp": 439439493,
    
        "services": {
          "service": [
            {
              "$id": "9bdd14ddad8465b6ee3fdd174b5d5bd2",
              "type": "bootstrapper",
              "version": "1.0",
              "methods": {
                "method": {
                  "name": "services-get",
                  "uri": "https://bootstrapper.example.com/services-get"
                }
              }
            },
            {
              "$id": "596c4577a4efb2a13ded43a3851b7e51577ad186",
              "type": "bootstrapped-finders",
              "version": "1.0",
              "methods": {
                "method": {
                  "name": "finders-get",
                  "uri": "https://finders.example.com/finders-get"
                }
              }
            },
            {
              "$id": "596c4577a4efb2a13ded43a3851b7e51577ad186",
              "type": "certificates",
              "version": "1.0",
              "methods": {
                "method": {
                  "name": "certificates-get",
                  "uri": "https://certificates.example.com/certificates-get"
                }
              }
            },
            {
              "$id": "d0b528b3f8e66455d154b1deac1e357e",
              "type": "namespace-grant",
              "version": "1.0",
              "methods": {
                "method": [
                  {
                    "name": "namespace-grant-inner-frame",
                    "uri": "https://grant.example.com/namespace-grant-inner-frame"
                  },
                  {
                    "name": "namespace-grant-admin-inner-frame",
                    "uri": "https://grant.example.com/namespace-grant-admin-inner-frame"
                  },
                  {
                    "name": "namespace-grant-preapproved-grant",
                    "uri": "https://grant.example.com/namespace-grant-preapproved-grant"
                  },
                  {
                    "name": "namespace-grant-validate",
                    "uri": "https://grant.example.com/namespace-grant-validate"
                  }
                ]
              }
            },
            {
              "$id": "d0b528b3f8e66455d154b1deac1e357e",
              "type": "identity-lockbox",
              "version": "1.0",
              "methods": {
                "method": [
                  {
                    "name": "lockbox-access",
                    "uri": "https://lockbox.example.com/lockbox-access"
                  },
                  {
                    "name": "lockbox-identities-update",
                    "uri": "https://lockbox.example.com/lockbox-identities-update"
                  },
                  {
                    "name": "lockbox-content-get",
                    "uri": "https://lockbox.example.com/lockbox-content-get"
                  },
                  {
                    "name": "lockbox-content-set",
                    "uri": "https://lockbox.example.com/lockbox-content-set"
                  }
                ]
              }
            },
            {
              "$id": "d0b528b3f8e66455d154b1deac1e357e",
              "type": "identity-lookup",
              "version": "1.0",
              "methods": {
                "method": [
                  {
                    "name": "identity-lookup-check",
                    "uri": "https://identity-lookup.example.com/identity-check"
                  },
                  {
                    "name": "identity-lookup",
                    "uri": "https://identity-lookup.example.com/identity-lookup"
                  }
                ]
              }
            },
            {
              "$id": "f98b4d1ff0f1acf3054fefc560866e61",
              "type": "identity",
              "version": "1.0",
              "methods": {
                "method": [
                  {
                    "name": "identity-access-inner-frame",
                    "uri": "https://identity.example.com/identity-access-inner-frame"
                  },
                  {
                    "name": "identity-access-validate",
                    "uri": "https://identity.example.com/identity-access-validate"
                  },
                  {
                    "name": "identity-lookup-update",
                    "uri": "https://identity.example.com/identity-lookup-update"
                  },
                  {
                    "name": "identity-sign",
                    "uri": "https://identity.example.com/identity-sign"
                  }
                ]
              }
            },
            {
              "$id": "2b24016d58b04f0a3b157a82ddd5f18b44d8912a",
              "type": "peer",
              "version": "1.0",
              "methods": {
                "method": {
                  "name": "peer-services-get",
                  "uri": "https://peer.example.com/peer-services-get"
                }
              }
            },        {
              "$id": "db144bb314f8e018f103033cbba7d52e",
              "type": "salt",
              "version": "1.0",
              "methods": {
                "method": {
                  "name": "signed-salt-get",
                  "uri": "https://salt.example.com/signed-salt-get"
                }
              }
            },
            {
              "$id": "db144bb314f8e018f103033cbba7d52e",
              "type": "example",
              "version": "1.0",
              "key": {
                "$id": "8cd14dda3...d5bd2",
                "domain": "example.com",
                "service": "something"
              },
              "methods": {
                "method": {
                  "name": "example-method",
                  "uri": "peer://example.com/5ff106c7db894b96a1432c35c246f36d8414bbd3"
                }
              }
            }
          ]
        }
      }
    }

 ### Example (redirect)

    {
      "request": {
        "$domain": "example.com",
        "$appid": "xyz123",
        "$handler": "bootstrapper",
        "$method": "services-get"
      }
    }
.

    {
      "result": {
        "$domain": "example.com",
        "$handler": "bootstrapper",
        "$method": "services-get",
    
        "error": {
          "$id": 302,
          "#text": "Found",
          "location": "http://someserver.com/services-get"
        }
      }
    }


Bootstrapped Finder Service Requests
====================================

Finders Get Request
-------------------

### Purpose

This request returns a list random possible peer finders that a client can attempt a connection for the sake of registering or finding other peers.

### Inputs

The total number of server entries desired (which the server can choose to ignore and return less servers than requested, but never more).

### Returns

Returns a list of Finders containing the following information for each Finder:

  * Finder ID - the unique ID that represents this finder in the system
  * Array of protocols supported, with each defining:
    * Transport - a string describing the type of transport supported
    * host record [or pre-resolved comma separated IP:port pair locations] - for example for "multiplexed-json/tcp" lookup type is SRV with _finder._tcp.domain.com
  * Public key for the finder - Can be either the full X.509 certificate or a key name lookup for certificates returned from the certificate server
  * Weight / priority - default values for SRV like weight / priority when SRV entry is pre-resolved IP:port pairs
  * Geographic region ID - (optional) each server belongs to a logical geographic region (clients can organize servers into geographic regions for fail over reasons)
  * Created - the epoch when the finder registered itself to the Bootstrapped Finder service. A finder with the same ID but a newer created date should replace an existing finder with the same ID.
  * Expires - the epoch when this finder information should be discarded and a new finder fetched to replace the existing one. There is no guarantee the finder will remain online for this period of time as this is a recommendation only. Should initiated communication to a finder server fail, the finder information might be considered no longer valid as the finder server might be gone.
  * Signed by the finder service

### Security Considerations

The client must ensure the server has an HTTPS certificate that was issued by a root certificate authority and that the certificate offered by the server is still within the X.509 validity date. The client should check the validity of each finder by verifying each finder was signed by a "Finder" service for the same domain as the requested Bootstrapper. The server does not need to verify a client's intentions.

The finder information can be cached and the client can reconnect to the same finder at will in the future. The finder server is considered transient though and may at any time disappear from offering service.

Each Finder should have its own X.509 certificate that it generates upon start-up and reports through whatever secure mechanism to the Bootstrapper Finder Service. This causes each finder to use it's own keying information which is not shared across finders. However, this is not a hard requirement and the Finders may use a common key across all Finders.

### Example

    {
      "request": {
        "$domain": "example.com",
        "$appid": "xyz123",
        "$handler": "bootstrapped-finders",
        "$method": "finders-get",
        "$id": "abd23",
    
        "servers": 2
      }
    }
.

    {
      "result": {
        "$domain": "example.com",
        "$appid": "xyz123",
        "$handler": "bootstrapped-finders",
        "$method": "finders-get",
        "$id": "abc123",
        "$timestamp": 439439493,
    
        "finders": {
          "finderBundle": [
            {
              "finder": {
                "$id": "4bf7fff50ef9bb07428af6294ae41434da175538",
                "protocols": {
                  "protocol": [
                    {
                      "transport": "multiplexed-json/tcp",
                      "host": "finders.example.com"
                    },
                    {
                      "transport": "multiplexed-json/secure-web-socket",
                      "host": "finders.example.com"
                    }
                  ]
                },
                "key": { "x509Data": "MIIDCCA0+gA...lVN" },
                "priority": 1,
                "weight": 1,
                "region": "1",
                "created": 588584945,
                "expires": 675754754
              },
              "signature": {
                "reference": "#4bf7fff50ef9bb07428af6294ae41434da175538",
                "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
                "digestValue": "jeirjLr...ta6skoV5/A8Q38Gj4j323=",
                "digestSigned": "DE...fGM~C0/Ez=",
                "key": {
                  "$id": "9bdd14dda3f...dd174b5d5bd2",
                  "domain": "example.org",
                  "service": "finder"
                }
              }
            },
            {
              "finder": {
                "$id": "a7f0c5df6d118ee2a16309bc8110bce009f7e318",
                "protocols": {
                  "protocol": [
                    {
                       "transport": "multiplex-json/tcp",
                       "host": "100.200.100.1:4032,5.6.7.8:4032"
                    },
                    {
                       "transport": "multiplex-json/secure-web-socket",
                       "host": "ip100-200-100-1.finder.example.com"
                    }
                  ]
                },
                "key": { "x509Data": "MIID5A0+gA...lVN" },
                "priority": 10,
                "weight": 0,
                "region": 1
              },
              "signature": {
                "reference": "#a7f0c5df6d118ee2a16309bc8110bce009f7e318",
                "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
                "digestValue": "YTdmMGM1ZGY2Z...DExOGVlMmExNjMwJjZTAwOWY3ZTMxOA==",
                "digestSigned": "OjY2OjZl...OjZhOjcyOjY2OjcyOjcyIChsZW5ndGg9OSk=",
                "key": {
                  "$id": "9bdd14dda3f...dd174b5d5bd2",
                  "domain": "example.org",
                  "service": "finder"
                }
              }
            }
          ]
        }
      }
    }


Certificates Service Requests
=============================

Certificates Get Request
------------------------

### Purpose

This request returns a list of public key X509 certificates used for signing in the domain for every service.

### Inputs

None.

### Returns

Returns a list of service certificates containing the following information for each certificate:

  * Certificate ID
  * Service name
  * Expiry
  * X.509 public key certificate
  * Signed by the Boostrapper service

### Security Considerations

The client must ensure the server has an HTTPS certificate that was issued by a root certificate authority and that the certificate offered by the server is still within the X.509 validity date. The server does not need to verify a client's intentions. The client should verify that each key was signed correctly from the Bootstrapper service key. This allows the clients to cache the certificate bundles while avoiding potential tampering.

### Example

    {
      "request": {
        "$domain": "example.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "certificates",
        "$method": "certificates-get"
      }
    }
.

    {
      "result": {
        "$domain": "example.com",
        "$appid": "xyz123",
        "$id": "abc123",
        "$handler": "certificates",
        "$method": "certificates-get",
        "$timestamp": 439439493,
    
        "certificates": {
          "certificateBundle": [
            {
              "certificate": {
                "$id": "4bf7fff50ef9bb07428af6294ae41434da175538",
                "service": "finder",
                "expires": 48348383,
                "key": { "x509Data": "MIIDCCA0+gA...lVN" }
              },
              "signature": {
                "reference": "#4bf7fff50ef9bb07428af6294ae41434da175538",
                "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
                "digestValue": "jeirjLrta6skoV5/A8Q38Gj4j323=",
                "digestSigned": "DEf...GM~C0/Ez=",
                "key": {
                  "$id": "9bdd14...dda3fddd5bd2",
                  "domain": "example.com",
                  "service": "bootstrapper"
                }
              }
            },
            {
              "certificate": {
                "$id": "9bdd14...dda3fddd5bd2",
                "service": "bootstrapper",
                "expires": 48348383,
                "key": { "x509Data": "OWJkZD...GQ1YmQy=" }
              },
              "signature": {
                "reference": "#9bdd14...dda3fddd5bd2",
                "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
                "digestValue": "amVpcmpMcn...RhNnNrb1Y1L0E4UTM4R2o0ajMyMz0=",
                "digestSigned": "YW1WcGNtcE1jb...lJoTm5OcmIxWTFMMEU0VVRNNFIybzBhak15TXowPQ==",
                "key": {
                  "$id": "9bdd14...dda3fddd5bd2",
                  "domain": "example.com",
                  "service": "bootstrapper"
                }
              }
            },
            { ... }
          ]
        }
      }
    }


Namespace Grant Service Requests
================================

The Namespace Grant Service is used to verify that a user has knowingly granted a 3rd party user agent the right to access various network services. A web page from a trusted source is used to verify a user's intention.

NOTE: Services that normally issue user decided "namespace grant challenges" can opt to not issue challenges for trusted applications.


Namespace Grant Inner Frame
---------------------------

### Purpose

This inner frame is loaded from the outer application frame. The inner frame holds the namespace grant page for the namespace grant service. The inner / outer frames send information to / from each other via JavaScript posted messages. The inner page can display the namespace grant page from the trusted source, allowing the user to grant permission to the application requesting access to the namespaces. The outer and inner page are rendered inside a browser window and contains sufficient display size to allow the user to see what information is being granted.

### Inputs

None.

### Returns

None.

### Security Considerations

### Example


Namespace Grant Window Request
------------------------------

### Purpose

This request notification is sent from the inner frame to the outer window as a posted message. This allows the inner window to notify the outer window it's ready to start processing requests, or when browser visibility is required.

### Inputs

  * Ready
    * true - notify the login window is ready to receive messages
  * Visibility:
    * true - notify the login window needs visibility

### Returns

Success or failure.

### Security Considerations

### Example

    {
      "request": {
        "$domain": "provider.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "namespace-grant",
        "$method": "namespace-grant-window",
    
        "browser": {
          "ready": true,
          "visibility": true
        }
      }
    }
.

    {
      "result": {
        "$domain": "provider.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "namespace-grant",
        "$method": "namespace-grant-window",
        "$timestamp": 439439493
      }
    }


Namespace Grant Start Notification
----------------------------------

### Purpose

Once the browser window receives notification that it is ready, this request is sent to the inner frame by the outer frame to give the inner frame the needed challenge information to start the grant process.

### Inputs

  * Agent
    * User agent - the user agent identification for the product, typically "name/version (os/system)"
    * Name - a human readable friendly name for the product
    * Image - a human visual image for the brand that must be square in shape.
    * Agent URL - a web page that can be rendered in a browser to obtain more information about the agent
  * List of grant service challenges containing:
    * ID - a challenge ID that the server generated which the client application will have to authorize
    * Name - a human readable name for the service requesting the challenge
    * Image - a branded image representing the service requesting the challenge
    * URL - a browser URL the user can go to obtain more information about this service requesting the challenge
    * List of namespace URLs granted to the grant challenge
  * Browser information
    * Visibility - the browser window is being shown in what state
      * "visible" - the browser window is visible
      * "hidden" - the browser window is hidden and cannot be shown
      * "visible-on-demand" - the browser window is hidden but can be rendered visible via a request posted to the outer frame (note: if rendered inside an application, the application can show the window in a hidden state to start and the browser window can become visible only when the user needs to enter some credentials)
    * Popup
      * "allow"- popups windows / new tabs are allowed to be opened
      * "deny" - popup windows / new tables are not allowed to be opened
    * Outer frame reload URL - a URL to reload the outer frame should the grant process have to replace the outer frame's window with its own URL. Once the outer frame is reloaded the inner frame page is reloaded as well allowing the inner frame to send the completion request.

### Returns

None.

### Security Considerations

### Example

    {
      "notify": {
        "$domain": "provider.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "namespace-grant",
        "$method": "namespace-grant-start",
    
        "agent": {
          "userAgent": "hookflash/1.0.1001a (iOS/iPad)",
          "name": "hookflash",
          "image": "https://hookflash.com/brandsquare.png",
          "url": "https://hookflash.com/agentinfo/"
        },
    
        "namespaceGrantChallenges": {
    
           "namespaceGrantChallenge": [
             {
              "$id": "20651257fecbe8436cea6bfd3277fec1223ebd63",
              "name": "Provider Lockbox Service",
              "image": "https://provider.com/lockbox/lockbox.png",
              "url": "https://provider.com/lockbox/",
    
              "namespaces": {
                "namespace": [
                  {
                    "$id": "https://domain.com/pemissionname"
                  },
                  {
                    "$id": "https://other.com/pemissionname"
                  }
                ]
              }
            },
            {
              "$id": "1bbca957f2cb2802480b81c16b1f76176b762340",
              "name": "Provider Identity Service",
              "image": "https://provider.com/identity/identity.png",
              "url": "https://provider.com/identity/",
    
              "namespaces": {
                "namespace": [
                  {
                    "$id": "https://what.com/pemissionname"
                  },
                  {
                    "$id": "https://where.com/pemissionname"
                  }
                ]
              }
            }
          ]
        },
    
        "browser": {
          "visibility": "visible-on-demand",
          "popup": "deny",
          "outerFrameURL": "https://webapp.com/outerframe?reload=true"
        }
      }
    }


Namespace Grant Complete Notification
-------------------------------------

### Purpose

This notification is sent from the inner browser window to the outer window as a posted message to indicate that the grant process has completed.

###Inputs

  * List of grant service challenge bundle proofs containing:
    * ID - a challenge ID that the server generated which the client application will have to authorize
    * Name - a human readable name for the service requesting the challenge
    * Image - a branded image representing the service requesting the challenge
    * URL - a browser URL where the user can go to obtain more information about this service requesting the challenge
    * List of namespace URLs granted to the grant challenge
    * Signed by namespace grant service

### Returns

### Security Considerations

The resulting proof bundles will only contain challenges that have been approved and only contain the namespaces that were approved for the challenge.

### Example

    {
      "notify": {
        "$domain": "provider.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "namespace-grant",
        "$method": "namespace-grant-complete",
    
        "namespaceGrantChallengeBundles": {
    
          "namespaceGrantChallengeBundle:" [
            {
              "namespaceGrantChallenge": {
                "$id": "20651257fecbe8436cea6bfd3277fec1223ebd63",
                "name": "Provider Lockbox Service",
                "image": "https://provider.com/lockbox/lockbox.png",
                "url": "https://provider.com/lockbox/",
    
                "namespaces": {
                  "namespace": [
                    {
                      "$id": "https://domain.com/pemissionname"
                    },
                    {
                      "$id": "https://other.com/pemissionname"
                    }
                  ]
                }
              },
              "signature": {
                "reference": "#20651257fecbe8436cea6bfd3277fec1223ebd63",
                "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
                "digestValue": "IUe324k...oV5/A8Q38Gj45i4jddX=",
                "digestSigned": "MDAwMDAw...MGJ5dGVzLiBQbGVhc2UsIGQ=",
                "key": {
                  "$id": "b7ef37...4a0d58628d3",
                  "domain": "provider.com",
                  "service": "namespace-grant"
                }
              }
            },
            { 
              "namespaceGrantChallenge": {
                "$id": "1bbca957f2cb2802480b81c16b1f76176b762340",
                "name": "Provider Identity Service",
                "image": "https://provider.com/identity/identity.png",
                "url": "https://provider.com/identity/",
    
                "namespaces": {
                  "namespace": [
                    {
                      "$id": "https://what.com/pemissionname"
                    },
                    {
                      "$id": "https://where.com/pemissionname"
                    }
                  ]
                }
              },
              "signature": {
                "reference": "#1bbca957f2cb2802480b81c16b1f76176b762340",
                "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
                "digestValue": "ZnNhZnNkZ...GtsYWxzZmQNCg==",
                "digestSigned": "Wm5OaFpuTmtabk5...Vd4elptUU5DZz09=",
                "key": {
                  "$id": "b7ef37...4a0d58628d3",
                  "domain": "provider.com",
                  "service": "namespace-grant"
                }
              }
            }
          ]
        }
    
      }
    }

Identity Lockbox Service Requests
=================================

Lockbox Access Request
----------------------

### Purpose

This request obtains access to a lockbox. Access is granted by way of login proof to an identity that is allowed to have access to the lockbox.

### Inputs

  * Client nonce - a onetime use nonce, i.e. cryptographically random string
  * Identity information (optional, if logging in using an identity)
    * Identity access token - as returned from the "Identity Access Complete" notification
    * Proof of 'identity access secret' - proof required to validate that the 'identity access secret' is known, proof = hex(hmac(`<identity-access-secret>`, "identity-access-validate:" + `<identity>` + ":" + `<client-nonce>` + ":" + `<expires>` + ":" + `<identity-access-token>` + ":lockbox-access"))
    * Expiry of the proof for the 'identity access secret' - a window in which access secret proof is considered valid
    * Original identity URI
    * Identity provider (optional, required if identity does not include domain or if domain providing identity service is different)
  * Lockbox information
    * Lockbox domain - the domain hosting the lockbox
    * Lockbox account ID - (optional, if known) the assigned account ID for the lockbox
    * Lockbox key "hash" - (optional) hash of the lockbox key, hex(hash(`lockbox-key`)). If this hash specified matches the hash in the database associated with the account ID then this hash can be used to login to the lockbox account (by specifying the lockbox account ID). If validated identity information is present and the hash value does not match the hash value in the database then all the content values stored in the lockbox must be deleted (but the associated identities and the namespace grants can stay). This type of scenario can happen if a user's password was reset (where the lockbox key was lost in the process).
    * Lockbox reset flag - (optional) if specified and true, a new lockbox must be created for the identity specified (and an identity must be specified must be granted access) and this identity must become unassociated with any other existing lockbox accounts. If this identity was previously the only associated identity with a previous lockbox account then the previous lockbox account can be deleted entirely.
  * Agent
    * User agent - the user agent identification for the product, typically "name/version (os/system)"
    * Name - a human readable friendly name for the product
    * Image - a human visual image for the brand that must be square in shape.
    * Agent URL - a web page that can be rendered in a browser to obtain more information about the agent
  * Grant
    * ID - a client generated cryptographic unique ID representing the agent's permission to access the lockbox. Once this ID is generated by a client, it should remain stable in subsequent accesses (or a new permission grant will be required). This ID should remain secret to the client application and only given to trusted services.
  * List of namespace URLs where access is requested
    * namespace URL

### Returns

  * Lockbox information
    * Lockbox account ID - the assigned account ID for the lockbox
    * Lockbox access token - a verifiable token that is linked to the lockbox
    * Lockbox access secret - a secret passphrase that can be used in combination to the "lockbox access token" to provide proof of previous successful login
    * Lockbox access expiry - the window in which the access key is valid (and should be sufficiently in the distant future for use as a long term key)
    * Lockbox domain - the domain hosting the lockbox
    * Lockbox key "hash" - hash of the lockbox key as previously passed in and associated to the lockbox account.
  * Grant service challenge (optional, if challenge is required)
    * ID - a challenge ID that the server generated which the client application will have to authorize
    * Name - a human readable name for the service requesting the challenge
    * Image - a branded image representing the service requesting the challenge
    * URL - a browser URL where the user can go to obtain more information about this service requesting the challenge
    * Domains - a list of domains the service will accept trusted signatures as proof
  * Content list of data elements containing:
    * Namespace URL - the namespace URL is the ID where the data is stored, access was requested and access was previously granted
    * Updated - time-stamp (or version number) of when entries in the namespace were last updated
  * List of identities attached to the lockbox
    * Original identity URI
    * Identity provider (optional, required if identity does not include domain or if domain providing identity service is different)

### Security Considerations

Access to the lockbox does not grant access to the contents of the lockbox. The lockbox key must be obtained through an alternative method. Upon the server seeing namespaces used in conjunction with a grant ID where the namespace has not previously been granted, the lockbox will issue a "grant service challenge" to verify the user wishes to grant access to all those namespaces.

The server will validate the identity login via the identity service to access the account or validate the client has the correct lockbox key hash to access the account. An identity that has a different provider is considered a different identity. Thus an identity is deemed unique by its identity and its identity provider combined.

If the lockbox reset flag is specified then a new account is created based on the identity and the existing account remains associated to the old identities, or the old account is removed if no other identities remain associated.

If the lockbox key hash does not match for the account but the identity access passed into the account is valid and matches the account ID used then all data in all namespaces for the account must be wiped out. The lockbox key hash must become updated with the new key hash.

### Example

    {
      "request": {
        "$domain": "domain.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "identity-lockbox",
        "$method": "lockbox-access",
    
        "nonce": "ed585021eec72de8634ed1a5e24c66c2",
        "identity": {
          "accessToken": "a913c2c3314ce71aee554986204a349b",
          "accessSecretProof": "b7277a5e49b3f5ffa9a8cb1feb86125f75511988",
          "accessSecretProofExpires": 43843298934,
    
          "uri": "identity://domain.com/alice",
          "provider": "domain.com"
        },
    
        "lockbox": {
          "domain": "example.com",
          "hash": "cf69f9e4ed98bb739b4c72fc4fff403467014874"
        },
    
        "agent": {
          "userAgent": "hookflash/1.0.1001a (iOS/iPad)",
          "name": "hookflash",
          "image": "https://hookflash.com/brandsquare.png",
          "url": "https://hookflash.com/agentinfo/"
        },
    
        "grant": {
          "$id": "de0c8c10d692bc91c1a551f57a50d2f97ef67543"
        },
    
        "namespaces": {
          "namespace": [
            {
              "$id": "https://domain.com/pemissionname"
            },
            {
              "$id": "https://other.com/pemissionname"
            }
          ]
        }
    
      }
    }
.

    {
      "result": {
        "$domain": "provider.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "identity-lockbox",
        "$method": "lockbox-access",
        "$timestamp": 439439493,
    
        "lockbox": {
          "$id": "123456",
          "accessToken": "a913c2c3314ce71aee554986204a349b",
          "accessSecret": "b7277a5e49b3f5ffa9a8cb1feb86125f75511988",
          "accessSecretExpires": 8483943493,
    
          "domain": "example.com"
        },
    
        "namespaceGrantChallenge": {
          "$id": "20651257fecbe8436cea6bfd3277fec1223ebd63",
          "name": "Provider Lockbox Service",
          "image": "https://provider.com/lockbox/lockbox.png",
          "url": "https://provider.com/lockbox/",
          "domains": "trust.com,trust2.com"
        },
    
        "namespaces": {
          "namespace": [
            {
              "$id": "https://domain.com/pemissionname",
              "$updated": 4432324
            },
            {
              "$id": "https://other.com/pemissionname",
              "$updated": 4432324
            }
          ]
        },
    
        "identities": {
         "identity": [
            {
              "uri": "identity://domain.com/alice",
              "provider": "domain.com"
            },
            {
              "uri": "identity:phone:16045551212",
              "provider": "example.com"
            }
          ]
        }
      }
    }

Lockbox Access Validate Request
-------------------------------

### Purpose

This request proves that a lockbox access is valid and can be used to validate a lockbox access is successful by way of a 3rd party.

### Inputs

  * Client nonce - a onetime use nonce, i.e. cryptographically random string
  * Purpose - reason for validation (each service using this validation should have a unique purpose string)
  * Lockbox information
    * Lockbox account ID - (optional) the assigned account ID for the lockbox, if specified the access token must validate the account ID as valid
    * Lockbox access token - a verifiable token that is linked to the lockbox
    * Proof of lockbox access secret' - proof required to validate that the lockbox access secret' is known, proof = hex(hmac(`<lockbox-access-secret>`, "lockbox-access-validate:" + `<client-nonce>` + ":" + `<expires>` + ":" + `<lockbox-access-token>` + ":" + `<purpose>`))
    * Expiry of the proof for the 'lockbox access secret' - a window in which access secret proof short term credentials are considered valid

### Returns

Success or failure.

### Security Considerations

### Example

    {
      "request": {
        "$domain": "provider.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "identity-lockbox",
        "$method": "lockbox-access-validate",
    
        "nonce": "ed585021eec72de8634ed1a5e24c66c2",
        "purpose": "whatever",
        "lockbox": {
          "$id": "123456",
          "accessToken": "a913c2c3314ce71aee554986204a349b",
          "accessSecretProof": "b7277a5e49b3f5ffa9a8cb1feb86125f75511988",
          "accessSecretProofExpires": 43843298934
        }
      }
    }
.

    {
      "result": {
        "$domain": "provider.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "identity-lockbox",
        "$method": "identity-access-validate",
        "$timestamp": 439439493
      }
    }

Lockbox Namespace Grant Challenge Validate Request
--------------------------------------------------

### Purpose

This request proves that the grant ID challenge is proven valid by way of the namespace grant service.

### Inputs

  * Client nonce - a onetime use nonce, i.e. cryptographically random string
  * Lockbox information
    * Lockbox access token - a verifiable token that is linked to the lockbox
    * Proof of lockbox access secret' - proof required to validate that the lockbox access secret' is known, proof = hex(hmac(`<lockbox-access-secret>`, "lockbox-access-validate:" + `<client-nonce>` + ":" + `<expires>` + ":" + `<lockbox-access-token>` + ":lockbox-namespace-grant-challenge-validate"))
    * Expiry of the proof for the 'lockbox access secret' - a window in which access secret proof short term credentials are considered valid
  * Grant service challenge as issued by the lockbox service bundled with signature as returned from the namespace grant service

### Returns

Success or failure.

### Security Considerations

The lockbox service will validate that the proof bundle is correct and if the challenge ID is suitably proven for the grant ID previously specified. Once correctly proven, the lockbox will allow the grant ID access to those namespaces for the lockbox account specified.

### Example

    {
      "request": {
        "$domain": "provider.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "identity-lockbox",
        "$method": "lockbox-namespace-grant-challenge-validate",
    
        "nonce": "ed585021eec72de8634ed1a5e24c66c2",
        "lockbox": {
          "accessToken": "a913c2c3314ce71aee554986204a349b",
          "accessSecretProof": "b7277a5e49b3f5ffa9a8cb1feb86125f75511988",
          "accessSecretProofExpires": 43843298934
        },
    
        "namespaceGrantChallengeBundle:" {
          "namespaceGrantChallenge": {
            "$id": "20651257fecbe8436cea6bfd3277fec1223ebd63",
            "name": "Provider Lockbox Service",
            "image": "https://provider.com/lockbox/lockbox.png",
            "url": "https://provider.com/lockbox/",
    
            "namespaces": {
              "namespace": [
                {
                  "$id": "https://domain.com/pemissionname"
                },
                {
                  "$id": "https://other.com/pemissionname"
                }
              ]
            }
          },
          "signature": {
            "reference": "#20651257fecbe8436cea6bfd3277fec1223ebd63",
            "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
            "digestValue": "IUe324k...oV5/A8Q38Gj45i4jddX=",
            "digestSigned": "MDAwMDAw...MGJ5dGVzLiBQbGVhc2UsIGQ=",
            "key": {
              "$id": "b7ef37...4a0d58628d3",
              "domain": "provider.com",
              "service": "namespace-grant"
            }
          }
        }
      }
    }
.

    {
      "result": {
        "$domain": "provider.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "identity-lockbox",
        "$method": "lockbox-namespace-grant-challenge-validate",
        "$timestamp": 439439493
      }
    }

Lockbox Identities Update Request
---------------------------------

### Purpose

This request updates the identities that are allowed to access the lockbox account.

### Inputs

  * Client nonce - a onetime use nonce, i.e. cryptographically random string
  * Lockbox information
    * Lockbox access token - a verifiable token that is linked to the lockbox
    * Proof of lockbox access secret' - proof required to validate that the lockbox access secret' is known, proof = hex(hmac(`<lockbox-access-secret>`, "lockbox-access-validate:" + `<client-nonce>` + ":" + `<expires>` + ":" + `<lockbox-access-token>` + ":lockbox-identities-update"))
    * Expiry of the proof for the 'lockbox access secret' - a window in which access secret proof short term credentials are considered valid
  * List of identities information
    * Disposition - "update" is used to add / update an identity and "remove" removes access to an identity
    * Identity access token - (optional, required if "update" is used), as returned from the "identity access complete" request
    * Proof of 'identity access secret' - (optional, required if "update" is used), proof required to validate that the 'identity access secret' is known, proof = hex(hmac(`<identity-access-secret>`, "identity-access-validate:" + `<identity>` + ":" + `<client-nonce>` + ":" + `<expires>` + ":" + `<identity-access-token>` + ":lockbox-access-update"))
    * Expiry of the proof for the 'identity access secret' - (optional, required if "update" is used) window in which access secret proof short term credentials are considered valid
    * Original identity URI
    * Identity provider (optional, required if identity does not include domain or if domain providing identity service is different)

### Returns

  * List of identities still attached to the lockbox o Original identity URI
    * Identity provider (optional, required if identity does not include domain or if domain providing identity service is different)

### Security Considerations

If all the identities associated to the lockbox are removed then the lockbox account is considered deleted.

### Example

    {
      "request": {
        "$domain": "domain.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "identity-lockbox",
        "$method": "lockbox-identities-update",
    
        "nonce": "ed585021eec72de8634ed1a5e24c66c2",
        "lockbox": {
          "accessToken": "a913c2c3314ce71aee554986204a349b",
          "accessSecretProof": "b7277a5e49b3f5ffa9a8cb1feb86125f75511988",
          "accessSecretProofExpires": 43843298934
        },
    
        "identities": {
         "identity": [
            {
              "$disposition": "update",
    
              "accessToken": "a913c2c3314ce71aee554986204a349b",
              "accessSecretProof": "b7277a5e49b3f5ffa9a8cb1feb86125f75511988",
              "accessSecretProofExpires": 43843298934,
    
              "uri": "identity://domain.com/alice",
              "provider": "domain.com"
            },
            {
              "$disposition": "remove",
    
              "uri": "identity:phone:16135551212",
              "provider": "example.com"
            }
          ]
        }
      }
    }
.

    {
      "result": {
        "$domain": "provider.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "identity-lockbox",
        "$method": "lockbox-identities-update",
        "$timestamp": 439439493,
    
        "identities": {
         "identity": [
            {
              "uri": "identity://domain.com/alice",
              "provider": "domain.com"
            },
            {
              "uri": "identity:phone:16045551212",
              "provider": "example.com"
            }
          ]
        }
      }
    }


Lockbox Content Get Request
---------------------------

### Purpose

This request retrieves data contained in the lockbox.

### Inputs

  * Client nonce - a onetime use nonce, i.e. cryptographically random string
  * Lockbox information
    * Lockbox access token - a verifiable token that is linked to the lockbox
    * Proof of lockbox access secret' - proof required to validate that the lockbox access secret' is known, proof = hex(hmac(`<lockbox-access-secret>`, "lockbox-access-validate:" + `<client-nonce>` + ":" + `<expires>` + ":" + `<lockbox-access-token>` + ":lockbox-content-get"))
    * Expiry of the proof for the 'lockbox access secret' - a window in which access secret proof short term credentials are considered valid
  * Content list of data elements containing:
    * Namespace URL - the namespace URL is the ID where the data is stored

### Returns

  * Content list of data elements containing:
    * Namespace URL - the namespace URL is the ID where the data is stored
    * Updated - time-stamp (or version number) of when entries in the namespace were last updated
    * List of values, each value encrypted with: encrypted value = `<salt-string>` + ":" + base64(key, value), where key = hmac(`<lockbox-key>`, "lockbox:" + `<permission-url>` + ":" + `<value-name>`), iv = hash(`<salt-string>`)

### Security Considerations

No value names within the same namespace URL should be identical.

### Example

    {
      "request": {
        "$domain": "domain.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "identity-lockbox",
        "$method": "lockbox-content-get",
    
        "nonce": "ed585021eec72de8634ed1a5e24c66c2",
        "lockbox": {
          "accessToken": "a913c2c3314ce71aee554986204a349b",
          "accessSecretProof": "b7277a5e49b3f5ffa9a8cb1feb86125f75511988",
          "accessSecretProofExpires": 43843298934
        },
    
        "namespaces": {
          "namespace": [
            {
              "$id": "https://domain.com/pemissionname"
            },
            {
              "$id": "https://other.com/pemissionname"
            }
          ]
        }
    
      }
    }
.

    {
      "result": {
        "$domain": "provider.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "identity-lockbox",
        "$method": "lockbox-content-get",
        "$timestamp": 439439493,
    
        "namespaces": {
          "namespace": [
            {
              "$id": "https://domain.com/pemissionname",
              "$updated": 5848843,
              "value1": "4f3f25da69fab2abb5c839158cc54e5a1320fac6:ZmRzbmZranNkbmF...a2pkc2tqZnNkbmtkc2puZmRhZnNzDQo=",
              "value2": "7779796a91b8a37d922a0338b0f71fcc672379d1:Zmpza2xham...Zsa2RzamxmYXNmYXNzZmRzYWZk"
            },
            {
              "$id": "https://other.com/pemissionname",
              "$updated": 5848845,
              "what1": "0ff33b2aa4b2da358cd7c04b420c10dc8c6e0521:ZmRzbmllZmJocmViaX...JmcXJicg0Kc2RmYQ0KZHNmYQ0Kcw0KZg==",
              "what2": "f19c58e42a6a6f62164de7bc3352da9fbacf117a:Wm1SemJtbG...ljZzBLYzJSbVlRMEtaSE5tWVEwS2N3MEtaZz09"
            }
          ]
        }
    
      }
    }


Lockbox Content Set Request
---------------------------

### Purpose

This request retrieves data contained in the lockbox.

### Inputs

  * Client nonce - a onetime use nonce, i.e. cryptographically random string
  * Lockbox information
    * Lockbox access token - a verifiable token that is linked to the lockbox
    * Proof of lockbox access secret' - proof required to validate that the lockbox access secret' is known, proof = hex(hmac(`<lockbox-access-secret>`, "lockbox-access-validate:" + `<client-nonce>` + ":" + `<expires>` + ":" + `<lockbox-access-token>` + ":lockbox-content-set"))
    * Expiry of the proof for the 'lockbox access secret' - a window in which access secret proof short term credentials are considered valid
  * Content list of data elements containing:
    * Namespace URL - the namespace URL is the ID where the data is stored
    * List of values, each value encrypted with: encrypted value = `<salt-string>` + ":" + base64(key, value), where key = hmac(`<lockbox-key>`, "lockbox:" + `<permission-url>` + ":" + `<value-name>`), iv = hash(`<salt-string>`), or a value of "-" to remove a value. The values are merged together with existing values or the values are removed if they contain a value of "-".

### Returns

### Security Considerations

No value names within the same permission URL should be identical. The salt string must be cryptographically randomly generated, and with sufficient length for use within an encryption IV.

### Example

    {
      "request": {
        "$domain": "domain.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "identity-lockbox",
        "$method": "lockbox-content-set",
    
        "nonce": "ed585021eec72de8634ed1a5e24c66c2",
        "lockbox": {
          "accessToken": "a913c2c3314ce71aee554986204a349b",
          "accessSecretProof": "b7277a5e49b3f5ffa9a8cb1feb86125f75511988",
          "accessSecretProofExpires": 43843298934
        },
    
        "namespaces":{
          "namespace": [
            {
              "$id": "https://domain.com/pemissionname",
              "value1": "4465e9c44b4bcdb9925c57365739d387899e2b91:ZmRzbmZranNkbmF...a2pkc2tqZnNkbmtkc2puZmRhZnNzDQo=",
              "value2": "-",
              "value3": "a49d7902da1690b1e16588969cf3beab77dae853:Zmpza2xham...Zsa2RzamxmYXNmYXNzZmRzYWZk"
            },
            {
              "$id": "https://other.com/pemissionname",
              "what1": "9d47f79a64157a9adc2c3cc6648e5dfe38b97805:ZmRzbmllZmJocmViaX...JmcXJicg0Kc2RmYQ0KZHNmYQ0Kcw0KZg==",
              "what2": "5b8e96e6083ba1c9d156e3af90e7aeeab8a55378:Wm1SemJtbG...ljZzBLYzJSbVlRMEtaSE5tWVEwS2N3MEtaZz09"
            }
          ]
        }
    
      }
    }
.

    {
      "result": {
        "$domain": "provider.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "identity-lockbox",
        "$method": "lockbox-content-get",
        "$timestamp": 439439493
      }
    }


Identity Lookup Service Requests
================================

The communication to the Identity Lookup is done over HTTPS exclusively whose HTTPS server certificate was signed by one of the trusted root Internet certification authorities.

Identity Lookup Check Request
-----------------------------

### Purpose

This request checks to see when the identity information last changed for particular identities and also determines which identities have contact information. Request will only return identities that resolve and they are returned in the same order they were requested.

### Inputs

List of providers containing:

  * Identity lookup base URI
  * Separator (default is ",")
  * List of:
    * Identities separated by "separator"

### Returns

List of resulting identities that resolve in the order requested as follows:

  * Original identity URI
  * Provider - service responsible for this identity
  * Last update timestamp - when the information associated to the identity was last updated

### Security Considerations

### Example

    {
      "request": {
        "$domain": "test.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "identity-lookup",
        "$method": "identity-lookup-check",
    
        "providers": {
          "provider": [
            {
              "base": "identity://domain.com/",
              "separator": ",",
              "identities": "alice,bob,fred"
            },
            {
              "base": "identity:phone:",
              "separator": ";",
              "identities": "16045551212;3814445551212"
            },
            {...}
          ]
        }
      }
    }
.

    {
      "result": {
        "$domain": "test.com",
        "$appid": "xyz123",
        "$id": "abc123",
        "$handler": "identity-lookup",
        "$method": "identity-lookup-check",
        "$timestamp": 439439493,
    
        "identities": {
          "identity": [
            {
              "uri": "identity://domain.com/alice",
              "updated": 5949594
            },
            {...},
            {
              "uri": "identity:phone:16045551212",
              "provider": "example.com",
              "updated": 5849594
            },
            {...},
            {
              "uri": "identity:email:alice@domain.com",
              "provider": "provider.com",
              "updated": 574443
            }
          ]
        }
      }
    }


Identity Lookup Request
-----------------------

### Purpose

This request resolves the identities to Peer Contacts. Request will only return identities that resolve and they are returned in the same order they were requested.

### Inputs

List of providers containing:

  * Identity lookup base URI
  * Separator (default is ",")
  * List of:
    * Identities separated by "separator"

### Returns

List of resulting identities that resolve in the order requested as follows:

  * Original identity URI
  * Provider - service responsible for this identity
  * Stable ID - a stable ID representing the user regardless of which identity is being used or the current peer contact ID
  * Public peer file
  * TTL expiry time-stamp - when must client do a recheck on the identity as the associated information might have changed
  * Priority / weight - "SRV-like" priority and weighting system to gage which identity discovered to be associated to the same peer contact have highest priority
  * Last update time-stamp - when the information associated to the identity was last updated
  * Identity display name - (optional), the display name to use with the identity
  * Identity rendered public profile URL - (optional), a web-page that can be rendered by the browser to display profile information about this identity
  * Programmatic public profile URL - (optional), a machine readable v-card like web-content-page that can be used to extract out common profile information
  * Public Feed URL - (optional), an RSS style feed representing the public activity for the user
  * Optional list of avatars containing:
    * Avatar name - (optional), name representing subject name of avatar (note: avatars with the same name are considered identical and thus are used to distinguish between varying sizes for the same avatar)
    * Avatar URL - URLs to download the avatar(s) associated with the identity
    * Avatar pixel width - (optional), pixel width of the avatar image
    * Avatar pixel height - (optional), pixel height of avatar image

### Security Considerations

### Example

    {
      "request": {
        "$domain": "test.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "identity-lookup",
        "$method": "identity-lookup",
    
        "providers": {
          "provider": [
            {
              "base": "identity://domain.com/",
              "separator": ",",
              "identities": "alice,bob,fred"
            },
            {
              "base": "identity:phone:",
              "separator": ";",
              "identities": "16045551212;3814445551212"
            },
            {...}
          ]
        }
      }
    }
.

    {
      "result": {
        "$domain": "test.com",
        "$appid": "xyz123",
        "$id": "abc123",
        "$handler": "identity-lookup",
        "$method": "identity-lookup",
        "$timestamp": 439439493,
    
        "identities": {
          "identity": [
            {
              "uri": "identity://domain.com/alice",
              "provider": "domain.com",
              "stableID": "123456",
              "peer": {...},
              "priority": 5,
              "weight": 1,
              "updated": 5949594,
              "expires": 58843493,
              "name": "Alice Applegate",
              "profile": "http://domain.com/user/alice/profile",
              "vprofile": "http://domain.com/user/alice/vcard",
              "feed": "http://domain.com/user/alice/feed",
              "avatars": {
                "avatar": { "url": "http://domain.com/user/alice/p" }
              },
              "identityProofBundle": {
                "identityProof": {
                  "$id": "b5dfaf2d00ca5ef3ed1a2aa7ec23c2db",
                  "contactProofBundle": {
                    "contactProof": {
                      "$id": "2d950c960b52c32a4766a148e8a39d0527110fee",
                      "stableID": "123456",
                      "contact": "peer://example.com/ab43bd44390dabc329192a392bef1",
                      "uri": "identity://domain.com/alice",
                      "created": 54593943,
                      "expires": 65439343
                    },
                    "signature": {
                      "reference": "#2d950c960b52c32a4766a148e8a39d0527110fee",
                      "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
                      "digestValue": "Wm1Sa...lptUT0=",
                      "digestSigned": "ZmRh...2FzZmQ=",
                      "key": { "uri": "peer://example.com/ab43bd44390dabc329192a392bef1" }
                    }
                  }
                },
                "signature": {
                  "reference": "#b5dfaf2d00ca5ef3ed1a2aa7ec23c2db",
                  "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
                  "digestValue": "IUe324koV5/A8Q38Gj45i4jddX=",
                  "digestSigned": "MDAwMDAwMGJ5dGVzLiBQbGVhc2UsIGQ=",
                  "key": {
                    "$id": "b7ef37...4a0d58628d3",
                    "domain": "domain.com",
                    "service": "identity"
                  }
                }
              }
            },
            {...},
            {
              "uri": "identity:phone:16045551212",
              "provider": "example.com",
              "stableID": "123456",
              "peer": {...},
              "priority": 1,
              "weight": 1,
              "updated": 5849594,
              "expires": 58843493,
              "identityProofBundle": { ... }
            },
            {...},
            {
              "uri": "identity:email:alice@domain.com",
              "provider": "provider.com",
              "stableID": "78312",
              "peer": {...},
              "priority": 1,
              "weight": 1,
              "updated": 574443,
              "expires": 58843493,
              "profile": "http://www.gravatar.com/205e460b479e2e5b48aec07710c08d50",
              "avatars": {
                "avatar": [
                  {
                    "name": "1",
                    "url": "http://www.gravatar.com/avatar/205e460b479e2e5b48aec07710c08d50?size=1",
                    "width": 100,
                    "height": 100
                  },
                  {
                    "name": "1",
                    "url": "http://www.gravatar.com/avatar/205e460b479e2e5b48aec07710c08d50?size=2",
                    "width": 200,
                    "height": 200
                  }
                ]
              },
              "identityProofBundle": { ... }
            }
          ]
        }
      }
    }


Identity Service Requests
=========================

Identity Access Inner Frame (web-page)
--------------------------------------

### Purpose

This inner frame is loaded from the outer application frame. The inner frame holds the login page for the identity. The inner / outer frames send information to / from each other via JavaScript posted messages. The inner page can display the identity provider's login page allowing the user to enter their identity credentials. The outer and inner page are rendered inside a browser window and contains sufficient display size to allow an identity provider to enter their credential information although the web view might start hidden to allow for auto-relogin (in which case there will be no rendered page for entering credential information).

### Inputs

None.

### Returns

None.

###Security Considerations

### Example


Identity Access Window Request
------------------------------

### Purpose

This request notification is sent from the inner frame to the outer frame as a posted message. This allows the inner window to notify the outer browser window that visibility is needed and / or if it's ready to start processing requests. Upon loading the inner frame must send to the outer frame that it is ready to start processing messaging.

### Inputs

  * Ready
    * true - notify the login window is ready to receive messages
  * Visibility:
    * true - notify the login window needs visibility

### Returns

Success or failure.

### Security Considerations

This notification is allowed to be sent more than once to the outer frame as needed. If the inner frame is being reloaded after having been replaced during the login process, the inner frame dies not need to resend this notification as it can immediately send the "Identity Access Complete" notification.

### Example

    {
      "request": {
        "$domain": "provider.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "identity",
        "$method": "identity-access-window",
    
        "browser": {
          "ready": true,
          "visibility": true
        }
      }
    }
.

    {
      "result": {
        "$domain": "provider.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "identity",
        "$method": "identity-access-window",
        "$timestamp": 439439493
      }
    }

Identity Access Start Notification
----------------------------------

### Purpose

Once the browser window receives notification that it is ready, this request is sent to the inner frame by the outer frame to give the inner frame the needed information to start the login process.

### Inputs

  * Agent
    * Product - the user agent identification for the product, typically "name/version (os/system)" information)
    * Name - a human readable friendly name for the product
    * Image - a human visual image for the brand that must be square in shape.
    * Agent URL - a web page that can be rendered in a browser to obtain more information about the agent
  * Base identity URI - base URI for identity (or full identity if known in advance)
  * Identity relogin key (optional) - a key to automatically relogin to an identity service when possible without prompting the user for a password and the meaning of the key is specific to the identity provider (the key is self-contained and includes all the information it needs to relogin but may not be capable of performing the relogin in which case the user will go through the normal login process)
  * Browser information
    * Visibility - the browser window is being shown in what state
      * "visible" - the browser window is visible
      * "hidden" - the browser window is hidden and cannot be shown
      * "visible-on-demand" - the browser window is hidden but can be rendered visible via a request posted to the outer frame (note: if rendered inside an application, the application can show the window in a hidden state to start and the browser window can become visible only when the user needs to enter some credentials)
    * Popup
      * "allow"- popups	windows/new tabs are allowed to	be opened
      * "deny" - popup windows/new tables are not allowed to be opened
    * Outer frame reload URL - a URL to reload the outer frame should the login process have to replace the outer frame's window with its own URL. Once the outer frame is reloaded the	inner frame page is reloaded as	well allowing the inner	frame to send the completion request.

### Returns

None.

### Security Considerations

If the full URI of the identity is specified, the client should attempt to relogin automatically to the identity (if possible).

The identity relogin key is specific to the provider. This key must be only stored in an encrypted fashion if it is stored somewhere (e.g. inside the lockbox). This key is optional and not required to be supported but should be used to facilitate the easy relogin to the identity service on other devices. This key should have a long lifetime but the lifetime is not known by the client application as a re-challenge can be issued by the identity service at any time without warning.

If the outer fame is being reloaded after haven been replaced, this notification should not be sent again.

Once the inner frame receives this notification it is allowed to replace the outer frame with its own page but it must bring back the outer page so the login process can be completed.

### Example

    {
      "notify": {
        "$domain": "provider.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "identity",
        "$method": "identity-access-start",
    
        "agent": {
          "userAgent": "hookflash/1.0.1001a (iOS/iPad)",
          "name": "hookflash",
          "image": "https://hookflash.com/brandsquare.png",
          "url": "https://hookflash.com/agentinfo/"
        },
    
        "identity": {
          "base": "identity://provider.com/",
          "reloginKey": "d2922f33a804c5f164a55210fe193327de7b2449-5007999b7734560b2c23fe81171af3e3-4c216c23"
        },
    
        "browser": {
          "visibility": "visible-on-demand",
          "popup": "deny",
          "outerFrameURL": "https://webapp.com/outerframe?reload=true"
        }
      }
    }


Identity Access Complete Notification
-------------------------------------

### Purpose

This notification is sent from the inner browser window to the outer window as a posted message to indicate that the login process has completed.

### Inputs

  * Identity information
    * Identity URI - the full identity URI of the logged in user
    * Identity provider - identity provider providing identity service
    * Identity access token - a verifiable token that is linked to the logged-in identity
    * Identity access secret - a secret passphrase that can be used in combination to the "identity access token" to provide proof of previous successful login
    * Identity access expiry - the window with sufficient long into-the-future time frame in which the access key long term credentials are valid
  * Lock box information (optional, if known)
      * Lockbox domain - if lockbox domain is known in advance, this is the domain for the lockbox to use
      * Lockbox key - this is client side base-64 encoded lockbox key.
      * Lockbox reset flag - this flag is used if the lockbox must be reset with a new password and all data within to be flushed.

### Returns

### Security Considerations

The lockbox key should be decrypted locally in the JavaScript using something unavailable in the server, for example the user's password. Other information should be combined to create the encryption / decryption key to ensure two unique users with the same password do not share the same encryption key.

An example formula might look like:

lockbox-key = decrypt(key, `<lockbox-key-encrypted>`), where key = hmac(key_strectch(`<user-password>`), `<user-id>`), iv = hash(`<user-salt>`)

Key stretching should be employed whenever using a weaker user generated non-cryptographically strong password. See: http://en.wikipedia.org/wiki/Key_stretching

By using information not stored on a server, this ensures that should the server be hacked that the servers do not contain the correct information to decrypt the lockbox key. The downside is that should the password change the encryption key will need to be decrypted with the existing user password then re-encrypted using the new password. Further, if the old password is lost then the lockbox key is also lost (and thus all associated content can no longer be decrypted).

### Example

    {
      "notify": {
        "$domain": "provider.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "identity",
        "$method": "identity-access-complete",
    
        "identity": {
          "accessToken": "a913c2c3314ce71aee554986204a349b",
          "accessSecret": "b7277a5e49b3f5ffa9a8cb1feb86125f75511988",
          "accessSecretExpires": 8483943493,
    
          "uri": "identity://domain.com/alice",
          "provider": "domain.com",
          "reloginKey": "d2922f33a804c5f164a55210fe193327de7b2449-5007999b7734560b2c23fe81171af3e3-4c216c23"
        },
    
        "lockbox": {
          "domain": "domain.com",
          "key": "V20x...IbGFWM0J5WTIxWlBRPT0=",
          "reset": false
        }
      }
    }


Identity Access Lockbox Update Request
--------------------------------------

### Purpose

This request is sent from the outer browser window to the inner window as a posted message to indicate that the login process has completed.

### Inputs

  * Client one time use nonce (cryptographically random string)
  * Identity information
    * Identity URI - the full identity URI of the logged in user
    * Identity provider - identity provider providing identity service
    * Identity access token - as returned from the "identity access complete" request
    * Proof of 'identity access secret' - proof required to validate that the 'identity access secret' is known, proof = hex(hmac(`<identity-access-secret>`, "identity-access-validate:" + `<identity>` + ":" + `<client-nonce>` + ":" + `<expires>` + ":" + `<identity-access-token>` + ":lockbox-update"))
    * Expiry of the proof for the 'identity access secret' - a window in which access secret proof short term credentials are considered valid
  * Lock box information
    * Lockbox domain - if lockbox domain is known in advance, this is the domain for the lockbox to use
    * Lockbox key - this is base-64 encoded lockbox key

### Returns

Success or failure.

### Security Considerations

The lockbox key should be encrypted locally in JavaScript before being sent a server. This ensures the server does not contain the correct information to be able to decrypt the lockbox key. See "Identity Access Complete".

The lockbox key should only be sent to trusted identity providers, which will act on the best interest of the user to protect the lockbox key.

### Example

    {
      "request": {
        "$domain": "provider.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "identity",
        "$method": "identity-access-lockbox-update",
    
        "nonce": "ed585021eec72de8634ed1a5e24c66c2",
        "identity": {
          "accessToken": "a913c2c3314ce71aee554986204a349b",
          "accessSecretProof": "b7277a5e49b3f5ffa9a8cb1feb86125f75511988",
          "accessSecretProofExpires": 43843298934,
       
          "uri": "identity://domain.com/alice",
          "provider": "domain.com"
        },
        "lockbox": {
          "domain": "domain.com",
          "key": "V20x...IbGFWM0J5WTIxWlBRPT0="
        }
      }
    }
.

    {
      "result": {
        "$domain": "provider.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "identity",
        "$method": "identity-access-lockbox-update",
        "$timestamp": 439439493
      }
    }


Identity Access Validate Request
--------------------------------

### Purpose

This request proves that an identity access is valid and can be used to validate an identity access is successful by way of a 3rd party.

### Inputs

  * Client nonce - a onetime use nonce, i.e. cryptographically random string
  * Purpose - reason for validation (each service using this validation should have a unique purpose string)
  * Identity information
    * Identity access token - as returned from the "identity access complete" request
    * Proof of 'identity access secret' - proof required to validate that the 'identity access secret' is known, proof = hex(hmac(`<identity-access-secret>`, "identity-access-validate:" + `<identity>` + ":" + `<client-nonce>` + ":" + `<expires>` + ":" + `<identity-access-token>` + ":" + `<purpose>`))
    * Expiry of the proof for the 'identity access secret' - a window in which access secret proof short term credentials are considered valid
    * Original identity URI
    * Identity provider (optional, required if identity does not include domain or if domain providing identity service is different)

### Returns

Success or failure.

### Security Considerations

### Example

    {
      "request": {
        "$domain": "provider.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "identity",
        "$method": "identity-access-validate",
    
        "nonce": "ed585021eec72de8634ed1a5e24c66c2",
        "purpose": "whatever",
        "identity": {
          "accessToken": "a913c2c3314ce71aee554986204a349b",
          "accessSecretProof": "b7277a5e49b3f5ffa9a8cb1feb86125f75511988",
          "accessSecretProofExpires": 43843298934,
    
          "uri": "identity://domain.com/alice",
          "provider": "domain.com"
        }
      }
    }
.

    {
      "result": {
        "$domain": "provider.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "identity",
        "$method": "identity-access-validate",
        "$timestamp": 439439493
      }
    }


Identity Lookup Update Request
------------------------------

### Purpose

This request proves that an identity login is valid and can be used to validate an identity login is successful by way of a 3rd party.

### Inputs

  * Client one time use nonce (cryptographically random string)
  * Lockbox information
    * Lockbox account ID - the assigned account ID for the lockbox
    * Lockbox domain - this is the domain for the lockbox to use
    * Lockbox access token - a verifiable token that is linked to the lockbox
    * Proof of 'lockbox access secret' - proof required to validate that the lockbox access secret' is known, proof = hex(hmac(`<lockbox-access-secret>`, "lockbox-access-validate:" + `<client-nonce>` + ":" + `<expires>` + ":" + `<lockbox-access-token>` + ":identity-lookup-update"))
    * Expiry of the proof for the 'lockbox access secret' - a window in which access secret proof short term credentials are considered valid
  * identity bundle information
    * Identity access token - as returned from the "identity access complete" request
    * Proof of 'identity access secret' - proof required to validate that the 'identity access secret' is known, proof = hex(hmac(`<identity-access-secret>`, "identity-access-validate:" + `<identity>` + ":" + `<client-nonce>` + ":" + `<expires>` + ":" + `<identity-access-token>` + ":identity-lookup-update"))
    * Expiry of the proof for the 'identity access secret' - a window in which access secret proof short term credentials are considered valid
    * Stable ID - a stable ID representing the user regardless of which identity is being used or the current peer contact ID, stable ID = hex(hash("stable-id:" + `<lockbox-domain>` + ":" + `<lockbox-account-id>`))
    * Identity URI - the full identity URI of the logged in user
    * Identity provider - identity provider providing identity service
    * Public peer file - the public peer file associated with the contact ID
    * Priority / weight - SRV like priority and weighting system to gage which identity discovered to be associated to the same peer contact have highest priority
    * contact proof bundle - signed bundle to be incorporated as part of the identity proof returned from identity-lookup
      * stable ID - same value as passed into identity information (as part of the signed bundle)
      * contact - the peer URI for the public peer file specified
      * Identity URI - the full identity URI of the logged in user
      * signed by public peer file specified (only if peer file is being set, otherwise no "identityBundle" will be present)

### Returns

Success or failure.

### Security Considerations

The server must validate the following:

  * the identity access token/secret proof are valid
  * the lockbox access and the identity access (via the lockbox-access-validate request)
  * the stable IDs have been calculated correctly
  * the identity URIs match those of the identity access token
  * the contact URI matches the public peer file
  * the contact proof bundle is signed correctly by the private key associated with the public peer file

### Example Association

    {
      "request": {
        "$domain": "provider.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "identity",
        "$method": "identity-lookup-update",
    
        "nonce": "ed585021eec72de8634ed1a5e24c66c2",
        "lockbox": {
          "$id": "123456",
          "domain": "domain.com",
          "accessToken": "a913c2c3314ce71aee554986204a349b",
          "accessSecretProof": "b7277a5e49b3f5ffa9a8cb1feb86125f75511988",
          "accessSecretProofExpires": 43843298934
        },
        "identity": {
          "accessToken": "a913c2c3314ce71aee554986204a349b",
          "accessSecretProof": "b7277a5e49b3f5ffa9a8cb1feb86125f75511988",
          "accessSecretProofExpires": 43843298934,
    
          "uri": "identity://domain.com/alice",
          "provider": "domain.com",
    
          "stableID": "0acc990c7b6e7d5cb9a3183d432e37776fb182bf",
          "peer": {...},
          "priority": 5,
          "weight": 1,
          "contactProofBundle": {
            "contactProof": {
              "$id": "2d950c960b52c32a4766a148e8a39d0527110fee",
              "stableID": "0acc990c7b6e7d5cb9a3183d432e37776fb182bf",
              "contact": "peer://example.com/ab43bd44390dabc329192a392bef1",
              "uri": "identity://domain.com/alice",
              "created": 54593943,
              "expires": 65439343
            },
            "signature": {
              "reference": "#2d950c960b52c32a4766a148e8a39d0527110fee",
              "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
              "digestValue": "Wm1Sa...lptUT0=",
              "digestSigned": "ZmRh...2FzZmQ=",
              "key": { "uri": "peer://example.com/ab43bd44390dabc329192a392bef1" }
            }
          }
        }
      }
    }
.

    {
      "result": {
        "$domain": "provider.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "identity",
        "$method": "identity-lookup-update",
        "$timestamp": 439439493
      }
    }

### Example Remove Association

    {
      "request": {
        "$domain": "provider.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "identity",
        "$method": "identity-lookup-update",
    
        "nonce": "ed585021eec72de8634ed1a5e24c66c2",
        "identity": {
          "accessToken": "a913c2c3314ce71aee554986204a349b",
          "accessSecretProof": "b7277a5e49b3f5ffa9a8cb1feb86125f75511988",
          "accessSecretProofExpires": 43843298934,
    
          "uri": "identity://domain.com/alice",
          "provider": "domain.com"      
        }
      }
    }
.

    {
      "result": {
        "$domain": "provider.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "identity",
        "$method": "identity-lookup-update",
        "$timestamp": 439439493
      }
    }


Peer Service
============

Peer Services Get Request
-------------------------

### Purpose

This request retrieves gets a list of peer contact services available to the peer contact.

### Inputs

  * Client nonce - a onetime use nonce, i.e. cryptographically random string
  * Lockbox information
    * Lockbox access token - a verifiable token that is linked to the lockbox
    * Proof of 'lockbox access secret' - proof required to validate that the lockbox access secret' is known, proof = hex(hmac(`<lockbox-access-secret>`, "lockbox-access-validate:" + `<client-nonce>` + ":" + `<expires>` + ":" + `<lockbox-access-token>` + ":peer-services-get"))
    * Expiry of the proof for the 'lockbox access secret' - a window in which access secret proof short term credentials are considered valid

### Returns

List of services available to peer contact services, containing:

  * Service type
  * Version
  * Expires - when the service must be refreshed because it's no longer considered valid
  * List of requests methods, which includes
    * Method name
    * URI
    * Other request specific information

### Security Considerations

### Example

    {
      "request": {
        "$domain": "domain.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "peer",
        "$method": "peer-services-get",
    
        "nonce": "ed585021eec72de8634ed1a5e24c66c2",
        "lockbox": {
          "accessToken": "a913c2c3314ce71aee554986204a349b",
          "accessSecretProof": "b7277a5e49b3f5ffa9a8cb1feb86125f75511988",
          "accessSecretProofExpires": 43843298934
        }
    
      }
    }
.

    {
      "result": {
        "$domain": "provider.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "peer",
        "$method": "peer-services-get",
        "$timestamp": 439439493,
    
        "services": {
          "service": [
            {
              "$id": "4e6a9ca60d92dfa5e872537f408066d02bdb55f2",
              "type": "turn",
              "version": "RFC5766",
              "expires": 493943,
              "methods": {
                "method": {
                  "name": "turn",
                  "host": "service.com",
                  "username": "id39392",
                  "password": "bdaaba26fa8ccac7807a786156b1f0fc87b2e28a"
                }
              }
            },
            {
              "$id": "5e6a9ca60d92dfa5e872537f408066d02bdb55f8",
              "type": "stun",
              "version": "RFC5389",
              "expires": 493943,
              "methods": {
                "method": {
                  "name": "stun",
                  "host": "service.com",
                  "username": "id39392",
                  "password": "bdaaba26fa8ccac7807a786156b1f0fc87b2e28a"
                }
              }
            }
          ]
        }
      }
    }



Peer Salt Service Protocol
==========================

Signed Salt Get Request
-----------------------

### Purpose

This request returns random salt as derived from a server and signed to prove authenticity of the salt.

### Inputs

  * Number of signed salts

### Returns

  * Total number of salts, where each salt has
    * Salt id - each salt is given a unique ID within the system
    * Salt - base 64 encoded cryptographically random binary salt
    * Signed by salt service's private key

Return one or more signed salt blobs for use in the peer files.

### Security Considerations

The client should verify signature was generated by the certificate was issued by the salt service if the same domain.

### Example

    {
      "request": {
        "$domain": "example.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "peer-salt",
        "$method": "signed-salt-get",
    
        "salts": 2
      }
    }
.

    {
      "result": {
        "$domain": "example.com",
        "$appid": "xyz123",
        "$id": "abc123",
        "$handler": "peer-salt",
        "$method": "signed-salt-get",
        "$timestamp": 439439493,
    
        "salts": {
          "saltBundle": [
            {
              "salt": {
                "$id": "f2e2ba4ba900e3b78d0d8524f0888f2b57d1bf91",
                "#text": "fdjfdsE2443lfkXEnek..343o="
              },
              "signature": {
                "reference": "#f2e2ba4ba900e3b78d0d8524f0888f2b57d1bf91",
                "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
                "digestValue": "IUe324ko...V5/A8Q38Gj45i4jddX=",
                "digestSigned": "DEf...GM~C0/Ez=",
                "key": {
                  "$id": "db144bb314103033cbba7d52e",
                  "domain": "example.com",
                  "service": "salt"
                }
              }
            },
            {
              "salt": {
                "$id": "35959a33d4eafac97b9d068cba32a8c6c6fd463a",
                "#text": "prfd+dsE243lfkXEnek..8rz=="
              },
              "signature": {
                "reference": "#35959a33d4eafac97b9d068cba32a8c6c6fd463a",
                "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
                "digestValue": "4Jee4kfd/oV5Af8Q3g48Gjg4n5iw4jzd8k=",
                "digestSigned": "Ttzf...eky5D/GM~C0=",
                "key": {
                  "$id": "db144bb314103033cbba7d52e",
                  "domain": "example.com",
                  "service": "salt"
                }
              }
            }
          ]
        }
      }
    }



Peer Common Protocol
====================

Peer Publish Request
--------------------

### Purpose

This method allows a peer to publish a document into the network where it can be subscribed to by other peers or groups.

### Inputs

  * Document name - full path, including namespace
  * Document version - first version must start at 1 and all others must be +1 from previous
  * Document base version - (optional), must be present if sending an "json-diff" document; the base version must be included to know what the base version was used to compute the differences. This base version must match the last published version by the receiver of the publish request or a 409 conflict will be returned.
  * Document lineage - for v1 documents, it is recommend to use the epoch but the server may replace with its own value in the result (which must be used in subsequent updates); the lineage must match between updates to the same document; the lineage value is to prevent conflicts when performing document deletions
  * Chunk number - (optional), "1/1" is assumed - to allow upload of multiple chunks of the document (note: not all documents support chunking)
  * Scope of where the document resides - associated to "location", or "contact"; the "location" scope is a private namespace only writable to the current session location; the "contact" scope is a namespace shared by all locations for the same contact (or through a special processer is shared amongst all users
  * Lifetime of document - i.e. "session" or "permanent"
  * Expiry of document - (optional), epoch of when document must expire
  * Encoding - (optional), "json" is assumed, options are "json", "binary-base64"
  * "Publish to relationships" - list of:
    * Relationships contact file name (e.g. "/hookflash.com/authorization-list/1.0/whitelist" or "/hookflash.com/authorization-list/1.0/adhoc-subscribers"). The scope for relationship documents is always "location". However, specialized document processors can generate "on-the-fly" relationship lists.
    * Permission - one of:
      * "all"-allowallusersonthelisttosubscribe,fetchandreceivenotification about this document;
      * "none" - do not allow any users on the list to fetch and receive notification about this document;
      * "some" - allow only specific users listed within the relationship list to subscribe and receive notification about this document;

### Outputs

The document meta information as passed into the publish without the data itself, including an updated lineage should the server replace the lineage for version 1 documents.

### Security Considerations

The lineage value can only be changed and must be changed after a previous document of the same name has been deleted. The server must verify the lineage is identical to the current lineage for versions other than version 1 chunk 1. For version 1 chunk 1 documents, the server can replace the proposed lineage with its own value that must be used in subsequent updates of the document. The lineage value must increase in value from the previous value when the lineage changes.

Clients and servers should consider the document "newer" if it has a greater lineage value regardless if the version number is smaller.

The server must delete the document at the end of the lifetime.

When the client is delivering multiple chunks, the chunks must arrive in sequence. Any other document requests mid update will fail with error code 409 until the entire document has been delivered.

If using the json or json-diff scheme, the document chunks are post-pended together into a single document until all chunks are delivered and then processed as a whole. If using binary-base64 then the documents are merged together with white space removed and then decoded to binary when all chunks have arrived.

The "all" or "some" permissions for relationships that allow a contact to receive the published documents takes precedence over the "none" or implied "deny" if they the listed contact is not contained within the "some" list.

### Example

    {
      "request": {
        "$id": "abc123",
        "$handler": "peer-common",
        "$method": "peer-publish",
        "document": {
          "details": {
            "name": "/hookflash.com/presence/1.0/bd520f1...c0cc9b7ff528e83470e/883fa7...9533609131",
            "version": 12,
            "baseVersion": 10,
            "lineage": 5849943,
            "chunk": "1/12",
            "scope": "location",
            "contact": "peer://example.com/97a9f246018a491d14cee267dceedf8a4ce0367c",
            "location": "5cd9f6d9bff930edcc590a62625ba7695b4f805e",
            "lifetime": "session",
            "expires": 447837433,
            "mime": "text/json",
            "encoding": "json"
          },
          "publishToRelationships": {
            "relationships": [
              {
                "$name": "/hookflash.com/authorization-list/1.0/whitelist",
                "$allow": "all"
              },
              {
                "$name": "/hookflash.com/authorization-list/1.0/adhoc",
                "$allow": "all"
              },
              {
                "$name": "/hookflash.com/shared-groups/1.0/foobar",
                "$allow": "all"
              }
            ]
          },
          "data": {...}
        }
      }
    }
.

    {
      "result": {
        "$id": "abc123",
        "$handler": "peer-common",
        "$method": "peer-publish",
        "$timestamp": 13494934,
    
        "document": {
          "details": {
            "name": "/hookflash.com/presence/1.0/bd520f1d...cc9b7ff528e83470e/883fa7...9533609131",
            "version": 12,
            "lineage": 5849943,
            "chunk": "1/12",
            "scope": "location",
            "lifetime": "session",
            "expires": 4839543,
            "mime": "text/json",
            "encoding": "json"
          },
          "publishToRelationships": {
            "relationships": [
              {
                "$name": "/hookflash.com/authorization-list/1.0/whitelist",
                "$allow": "all"
              },
              {
                "$name": "/hookflash.com/authorization-list/1.0/adhoc",
                "$allow": "all"
              },
              {
                "$name": "/hookflash.com/shared-groups/1.0/foobar",
                "$allow": "all"
              }
            ]
          }
        }
      }
    }


Peer Get Request
----------------

### Purpose

This method allows a peer to fetch a previously publish a document from the network.

### Inputs

  * Document name - full path, including namespace
  * Document version in cache - (optional), if available
  * Document lineage in cache - (optional), if available
  * Scope of where the document resides - associated to "location", or "contact"; the "location" scope is a private namespace only readable from the current session location; the "contact" scope is a namespace shared by all locations for the same contact; the "global" namespace is shared by all contacts on the system globally
  * Contact from which to load the document - (optional), if "location" or "contact" is used
  * Location ID from which to load the document - (optional), if "location" is used
  * Chunk number - (optional), "1/1" is assumed; to allow upload of multiple chunks of the document, the server may decide to split the result into multiple chunks for easier transport. The client should respect the server's splitting and use this value instead of its own "1/x" value.

### Outputs

Previously published document split into chunks when appropriate.

### Security Considerations

The server must ensure the document is published to the contact that is requesting the document otherwise the server must return a 403 Forbidden.

The server can return any version and lineage greater than the cached version. If the latest version is equal to the cached version, the document result will contain the document meta information without the data.

The server will return any version number it choses equal or greater to the request version number but must adhere to the "json-diff" mechanism and give only the differences between the versions or "json" to give the latest version only without performing the differences.

The server will ignore the chunking denominator for chunk requested for the "1/1" chunk and require the denominator to be a value it expects instead for all other chunks requested.

If using the "json" or "json-diff" scheme, the document chunks are post-pended together into a single document until all chunks are delivered and then processed as a whole. If using binary-base64 then the documents are merged together with white space removed and then decoded to binary when all chunks have arrived.

The "publish to relationships" section is only returned if the contact requesting the document is the publisher of the document.

### Example

    {
      "request": {
        "$id": "abc123",
        "$handler": "peer-common",
        "$method": "peer-get",
    
        "document": {
          "details": {
            "name": "/hookflash.com/presence/1.0/bd520f1dbaa...9b7ff528e83470e/883fa7...9533609131",
            "version": 12,
            "lineage": 39239392,
            "scope": "location",
            "contact": "peer://example.ecom/ea00ede4405c99be9ae45739ebfe57d5",
            "location": "524e609f337663bdbf54f7ef47d23ca9",
            "chunk": "1/1"
          }
        }
      }
    }
.

    {
      "result": {
        "$id": "abc123",
        "$handler": "peer-common",
        "$method": "peer-get",
        "$timestamp": 13494934,
    
        "document": {
          "details": {
            "name": "/hookflash.com/presence/1.0/bd520f1...c0cc9b7ff528e83470e/883fa7...9533609131",
            "version": 12,
            "lineage": 39239392,
            "chunk": "1/10",
            "scope": "location",
            "contact": "peer://example.com/ea00ede4405c99be9ae45739ebfe57d5",
            "location": "524e609f337663bdbf54f7ef47d23ca9",
            "lifetime": "session",
            "expires": 45747885743,
            "mime": "text/json",
            "encoding": "json"
          },
          "publishToRelationships": {
            "relationships": [
              {
                "$name": "/hookflash.com/authorization-list/1.0/whitelist",
                "$allow": "all"
              },
              {
                "$name": "/hookflash.com/authorization-list/1.0/adhoc",
                "$allow": "all"
              },
              {
                "$name": "/hookflash.com/shared-groups/1.0/foobar",
                "$allow": "all"
              }
            ]
          },
          "data": "..."
        }
      }
    }


Peer Delete Request
-------------------

### Purpose

This method allows a peer delete a previously publish a document from the network.

### Inputs

  * Document name - full path, including namespace
  * Document version - (optional), if specified the version number must match the last published version number or a conflict is returned
  * Document lineage - (optional), if specified the lineage number must match the lineage of the last published version of the document or a conflict is returned
  * Scope of where the document resides - associated to "location", or "contact"; the "location" scope is a private namespace only readable from the current session location; the "contact" scope is a namespace shared by all locations for the same contact; the "global" namespace is shared by all contacts on the system globally

### Outputs

Success or failure.

### Security Considerations

The contact owner of the document is the only entity allowed to delete the document.

If the document version or lineage is specified then the document version and lineage must match the last published version or the request is rejected with a 409 Conflict error.

### Example

    {
      "request": {
        "$id": "abc123",
        "$handler": "peer-common",
        "$method": "peer-delete",
    
        "document": {
          "details": {
            "name": "/hookflash.com/presence/1.0/bd520f1db...b7ff528e83470e/883fa7...9533609131",
            "version": 12,
            "lineage": 39239392,
            "scope": "location"
          }
        }
      }
    }
.

    {
      "result": {
        "$id": "abc123",
        "$handler": "peer-common",
        "$method": "peer-delete",
        "$timestamp": 13494934
      }
    }


Peer Subscribe Request
----------------------

### Purpose

This method allows a peer to subscribe to all documents it is authorized to fetch within a namespace and within its relationships.

### Inputs

  * Documents base path/name - full path base to monitor with optional "*" for partial paths
  * Relationships to subscribe, containing:
    * Name of relationships document
    * Which contacts within the relationships to subscribe
      * "all" - subscribe to all relationships
      * "none" - remove all subscriptions to any relationship
      * "some" - change relationships to subscribe to the listed contacts
      * "add" - add some contacts to subscribe within the relationships
      * "remove" - remove some contacts to subscribe with the relationships

### Outputs

Returns the resulting merged active subscription.

### Security Considerations

The server only allows subscriptions where permissions allow.

### Example

    {
      "request": {
        "$id": "abc123",
        "$handler": "peer-common",
        "$method": "peer-subscribe",
    
        "document": {
          "name": "/hookflash.com/presence/1.0/",
          "subscribeToRelationships": {
            "relationships": [
              {
                "$name": "/hookflash.com/authorization-list/1.0/whitelist",
                "$subscribe": "all"
              },
              {
                "$name": "/hookflash.com/authorization-list/1.0/adhoc",
                "$subscribe": "add",
                "contact": "peer://example.com/bd520f1dbaa13c0cc9b7ff528e83470e"
              },
              {
                "$name": "/hookflash.com/shared-groups/1.0/foobar",
                "$subscribe": "all"
              }
            ]
          }
        }
      }
    }
.

    {
      "result": {
        "$id": "abc123",
        "$handler": "peer-common",
        "$method": "peer-subscribe",
        "$timestamp": 13494934,
    
        "document": {
          "name": "/hookflash.com/presence/1.0/",
          "subscribeToRelationships": {
            "relationships": [
              {
                "$name": "/hookflash.com/authorization-list/1.0/whitelist",
                "$subscribe": "all"
              },
              {
                "$name": "/hookflash.com/authorization-list/1.0/adhoc",
                "$subscribe": "some",
                "contact": [
                  "peer://example.com/bd520f1dbaa13c0cc9b7ff528e83470e",
                  "peer://example.com/8d17a88e8d42ffbd138f3895ec45375c"
                ]
              },
              {
                "$name": "/hookflash.com/shared-groups/1.0/foobar",
                "$subscribe": "all"
              }
            ]
          }
        }
      }
    }


Peer Publish Notify
-------------------

### Purpose

This method notifies a peer that a document has been updated.

### Inputs

  * Document name - full path, including namespace
  * Document version - if "0" then the document for the lineage is deleted
  * Document lineage
  * Scope of where the document resides - associated to "location", or "contact" or "global"; the "location" scope is a private namespace only writable to the current session location; the "contact" scope is a namespace shared by all locations for the same contact; the "global" namespace is shared by all contacts on the system globally
  * Contact id - the contact that published the document
  * Location id - the location where the document was published
  * Lifetime of document - i.e. "session" or "permanent"
  * Expiry of document - (optional)
  * Data - (optional), at the discretion of the server, the document can be delivered as part of the notify or held back which will require the client to fetch later if the client wishes to update manually

### Outputs

None.

### Security Considerations

If a client wants to download a document about which notification was received, a client should attempt to use the documents from their cache rather than asking fetching the document again if the version of the document has already been fetched.

Clients should consider documents with newer lineage to be "newer" regardless of the version number. Documents of the same lineage are considered newer if they have the version number is greater.

### Example

    {
      "request": {
        "$id": "abc123",
        "$handler": "peer-common",
        "$method": "peer-publish-notify",
    
        "documents": {
          "document": {
            "details": {
              "name": "/hookflash.com/presence/1.0/bd520f1d...9b7ff528e83470e/883fa7...9533609131",
              "version": 12,
              "lineage": 43493943,
              "scope": "location",
              "contact": "peer://example.com/ea00ede4405c99be9ae45739ebfe57d5",
              "location": "524e609f337663bdbf54f7ef47d23ca9",
              "lifetime": "session",
              "expires": 44241421,
              "mime": "text/json",
              "encoding": "json"
            }
          },
          "data": {...}
        }
      }
    }
.

    {
      "result": {
        "$id": "abc123",
        "$handler": "peer-common",
        "$method": "document-publish-notify",
        "$timestamp": 13494934
      }
    }


Peer Finder Protocol
====================

Session Create Request
----------------------

### Purpose

Obtain a session token that represents the peer on the finder server so continuous proof of identity is not required for each request.

### Inputs

  * One time use session proof bundle, consisting of
    * Finder ID - where this request is to be processed
    * Peer contact making the request
    * Client nonce - cryptographically random one time use key
    * Expiry for the one time use token
    * Location details
      * Location ID
      * Device ID
      * IP
      * User agent
      * OS
      * System
      * Host
    * Public peer file
    * Signed by peer private key

### Outputs

  * Relay information (for relay connections):
    * access token - the access token needed for creating remote relay credentials that can be given to third parties to connect and relay information to this logged in application
    * access secret encrypted - the secret passphrase used for giving out relay credentials to 3rd parties, encrypted access secret = base64(rsa_encrypt(`<public-key-from-request-peer-file>`, `<access-secret>`))
  * Expiry epoch (when next a keep alive must be sent by)
  * Server agent
  * Signed by finder's certificate - uses finder's public key fingerprint as signature key reference

### Security Considerations

The server must validate that the token bundle has not expired.

The server must verify that the request has been signed by the peer's private peer file. The contact id specified in the bundle must match the calculated contact ID based on the included public peer file Section "A". The client nonce is used to prevent replay attacks to the server by ensuring the registration can only be used once on the server. The server should remember the client nonce has been seen for a reasonable period of time or at maximum until the request expiry time, and reject all requests with the same client nonce value. The finder ID specified in the bundle must match the finder ID of the finder.

If a Section-B of the public peer file is not present, the peer does not wish to be found in the network but may issue find requests.

### Example

    {
      "request": {
        "$domain": "domain.com",
        "$appid": "xyz123",
        "$id": "abc123",
        "$handler": "peer-finder",
        "$method": "session-create",
    
        "sessionProofBundle": {
          "sessionProof": {
            "$id": "6fc5c4ea068698ab31b6b6f75666808f",
    
            "finder": { "$id": "a7f0c5df6d118ee2a16309bc8110bce009f7e318" },
            "nonce": "09b11ed79d531a2ccd2756a2104abbbf77da10d6",
            "expires": 4848343494,
    
            "location": {
              "$id": "5a693555913da634c0b03139ec198bb8bad485ee",
              "contact": "peer://domain.com/920bd1d88e4cc3ba0f95e24ea9168e272ff03b3b",
              "details": {
                "device": { "$id": "e31fcab6582823b862b646980e2b5f4efad75c69" },
                "ip": "28.123.121.12",
                "userAgent": "hookflash/1.0.1001a (iOS/iPad)",
                "os": "iOS v4.3.5",
                "system": "iPad v2",
                "host": "foobar"
              }
            },
    
            "peer": {
              "$version": "1",
              "sectionBundle": {
                "section": {
                  "$id": "A",
                  ...
                }
              }
            }
          },
          "signature": {
            "reference": "#6fc5c4ea068698ab31b6b6f75666808f",
            "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
            "digestValue": "IUe324k...oV5/A8Q38Gj45i4jddX=",
            "digestSigned": "MDAwMDAw...MGJ5dGVzLiBQbGVhc2UsIGQ=",
            "key": { "uri": "peer://example.com/920bd1d88e4cc3ba0f95e24ea9168e272ff03b3b" }
          }
        }
      }
    }
.

    {
      "result": {
        "$domain": "domain.com",
        "$appid": "xyz123",
        "$id": "abc123",
        "$handler": "peer-finder",
        "$method": "session-create",
        "$timestamp": 13494934,
    
        "serverProofBundle": {
          "serverProof": {
            "$id": "edbd821123e9cfedf0285a95989ac461",
    
            "relay": {
              "accessToken": "9d934822ccca53ac6e16e279830f4ffe3cfe1d0e",
              "accessSecretEncrypted": "NWNmZGNkZWJmNDI5MDMzMmI2Mzc4YTYzZWMyZmVhNjA="
            },
        
            "server": "hooflash/1.0 (centos)",
            "expires": 483949923
          },
          "signature": {
            "reference": "#edbd821123e9cfedf0285a95989ac461",
            "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
            "digestValue": "NTRmZDRmNjBjYmJi...xMjdmYWQ4ODk0MQ==",
            "digestSigned": "TlRSbVpEUm1....GMwT1RjeE1qZG1ZV1E0T0RrME1RPT0=",
            "key": { "fingerprint": "54fd4f60cbbbf0077ec33c6447497127fad88941" }
          }
        }
    
      }
    }


Session Delete Request
----------------------

### Purpose

This request destroys an established session gracefully.

### Inputs

  * Locations - (optional), if specified without any sub location ID elements, then all locations including this will be unregistered (i.e. a complete system wide unregister), if the location element is missing then the current location associated with the session is unregistered
    * Location ID - (optional), for each location to unregister

### Outputs

  * The list of locations which were in fact unregistered, each listed by location ID

### Security Considerations

The client must have an established session to issue this request.

If the client is done with the current session it may immediately disconnect after receiving the response.

### Example

    {
      "request": {
        "$domain": "domain.com",
        "$appid": "xyz123",
        "$id": "abc123",
        "$handler": "peer-finder",
        "$method": "session-delete",
    
        "locations": {
          "location": [
            { "$id": "99609d8b1eb4c413813cbeb7c15137837d4037e9" },
            { "$id": "c8062df29e62d42a3dad60e57d9e84ba38e5ba47" }
          ]
        }
      }
    }
.

    {
      "result": {
        "$domain": "domain.com",
        "$appid": "xyz123",
        "$id": "abc123",
        "$handler": "peer-finder",
        "$method": "session-delete",
        "$timestamp": 13494934,
    
        "locations": {
          "location": [
            { "$id": "99609d8b1eb4c413813cbeb7c15137837d4037e9" },
            { "$id": "c8062df29e62d42a3dad60e57d9e84ba38e5ba47" }
          ]
        }
      }
    }


Session Keep-Alive Request
--------------------------

### Purpose

This request keeps a previous registered location alive in the location database.

### Inputs

None.

### Outputs

  * Expiry epoch (when next a keep alive must be sent by)

### Security Considerations 

The client must have an established session to issue this request.

Since the client and server are the only entities that know the session ID, the session can only be kept alive between machines without additional security. The Session Keep-Alive Request must arrive on the same Internet connection as the initial Session Create Request.

### Example

     {
      "request": {
        "$domain": "domain.com",
        "$appid": "xyz123",
        "$id": "abc123",
        "$handler": "peer-finder",
        "$method": "session-keep-alive"
      }
    }
.

    {
      "result": {
        "$domain": "domain.com",
        "$appid": "xyz123",
        "$id": "abc123",
        "$handler": "peer-finder",
        "$method": "session-keep-alive",
        "$timestamp": 13494934,
    
        "expires": 483949923
      }
    }


Channel Map Request
-------------------

### Purpose

Map a channel in the multiplex stream to a remote party. This request must be issued before messages can be sent on a client defined multiplexed channel number. This request can be issued outside of the context of a session.

### Inputs

   * channel number - channel number to allocate
   * nonce - a client defined one time use value
   * localContext - a context ID representing the context ID of the issuer of the request
   * remoteContext - a context ID representing the context ID of the remote relay where this request is being connected
   * relay access token - token as returned during peer finder session create (to connect to this session)
   * proof of relay access secret proof = hex(hash("proof:" + `<client-nonce>` + ":" + `<local-context>` + ":" + `<channel-number>` + ":" + `<expires>` + ":" + hex(hmac(`<relay-access-secret>`, "finder-relay-access-validate:" + `<relay-access-token>` + ":" + `<remote-context>` + ":channel-map"))))
   * access secret proof expiry - expiry time of the access secret proof

### Outputs


### Security Considerations

### Example

    {
      "request": {
        "$domain": "domain.com",
        "$appid": "xyz123",
        "$id": "abc123",
        "$handler": "peer-finder",
        "$method": "channel-map",
    
        "channel": 5,
        "nonce": "6771816e06b7b6f5d24f0d65df018dd256a31027",
        "relay": {
          "localContext": "a497f346db82ae34c2d9b7f62e34b9757d211bef",
          "remoteContext": "3b5db5880803d91f2ba9ca522c558fd1c545c28e",
          "accessToken": "9d934822ccca53ac6e16e279830f4ffe3cfe1d0e",
          "accessSecretProof": "SSByZWFsbHk...gaGF0ZSBTRFA=",
          "accessSecretProofExpires": 3884383
        }
      }
    }
.

    {
      "result": {
        "$domain": "domain.com",
        "$appid": "xyz123",
        "$id": "abc123",
        "$handler": "peer-finder",
        "$method": "channel-map",
        "$timestamp": 13494934
      }
    }


Channel Map Notify
------------------

### Purpose

This notification is sent from the finder server to a client with a session whose credential were used in a channel map request by another client. This notification gives context for a channel about to be received on a different channel.

### Inputs

   * channel number - channel number that the finder will allocate for use with the incoming channel
   * nonce - a finder server defined one time use value
   * localContext - the context ID representing the local session's context ID from where the relay access credentials were granted
   * remoteContext - a context ID representing the local context ID of the party party that issued the Channel Map Request
   * relay access token - token as returned during peer finder session create (to connect to this session)
   * proof of relay access secret proof = hex(hash("proof:" + `<client-nonce>` + ":" + `<remote-context>` + ":" + `<channel-number>` + ":" + `<expires>` + ":" + hex(hmac(`<relay-access-secret>`, "finder-relay-access-validate:" + `<relay-access-token>` + ":" + `<local-context>` + ":channel-map"))))
   * access secret proof expiry - expiry time of the access secret proof

### Outputs

### Security Considerations

### Example

    {
      "notify": {
        "$domain": "domain.com",
        "$appid": "xyz123",
        "$id": "abc123",
        "$handler": "peer-finder",
        "$method": "channel-map",
    
        "channel": 5,
        "nonce": "6771816e06b7b6f5d24f0d65df018dd256a31027",
        "relay": {
          "localContext": "3b5db5880803d91f2ba9ca522c558fd1c545c28e",
          "remoteContext": "a497f346db82ae34c2d9b7f62e34b9757d211bef",
          "accessToken": "9d934822ccca53ac6e16e279830f4ffe3cfe1d0e",
          "accessSecretProof": "SSByZWFsbHk...gaGF0ZSBTRFA=",
          "accessSecretProofExpires": 3884383
        }
      }
    }


Peer Location Find Request (single point to single point)
---------------------------------------------------------

### Request Flow

![Peer Location Find Request Flow](PeerLocationFindRequestFlow1.png)

Peer Location Find Request (A)
------------------------------

### Purpose

This is the request to find a peer that includes the proof of permission to contact the peer and the location information on how to contact the contacting peer. This request is sent from the requesting peer to the requesting peer's finder.

### Inputs
  * Cipher suite to use in the proof and for the encryption
  * Contact id of contact to be found
  * Client nonce - cryptographically random onetime use string
  * Find secret proof - i.e. hex(hmac(`<find-secret-from-remote-public-peer-file-section-B>`, "proof:" + `<client-nonce>` + ":" + expires))
  * Find proof expires
  * Context - the is the requester's part of the context ID. This identifier is combined with the remote peer's context to form the "requester" / "reply" context ID for MLS
  * Peer secret (encrypted) - peer secret is a random passphrase which is then encrypted using the public key of the peer receiving the find request - this key is password used for ICE negotiation, peer secret encrypted = base64(rsa_encrypt(`<remote-public-peer-file-public-key>`, `<peer-secret>`))
  * ICE username frag - the username fragment for ICE negotiation
  * ICE password encrypted - the password passphrase for ICE negotiation, encrypted data = hex(`<iv>`) + ":" + encrypt(`<key>`, `<ice-password>`), where key = hash(`<peer-secret>`), iv = `<random>`
  * Location details
    * Location ID of requesting location
    * Contact ID of requesting location
    * Location details
  * Location candidate contact addresses for peer location, each containing:
    * transport
    * if class is "ice":
      * transport
      * type - "host" or "srflx" or "prflx" or "relay"
      * IP
      * port
      * priority
      * related IP (optional, mandatory if type is "srflx" or "prflx" or "relay")
      * related port (optional, mandatory if type is "srflx" or "prflx" or "relay")
    * if class is "finder-relay":
      * transport - either "multiplexed-json-mls/tcp" or "multiplexed-json-mls/secure-web-socket"
      * type - "relay"
      * host - host where to connect to the finder relay
      * port - port to connect to the finder relay
      * access token - token as returned during peer finder session create
      * access secret proof (encrypted) - encrypted version of access secret proof, encrypted proof = hex(`<iv>`) + ":" + encrypt(`<key>`, `<proof>`), where proof = hex(hmac(`<access-secret>`, "finder-relay-access-validate:" + `<access-token>` + ":" + `<context>` + ":channel-map")), key = hash(`<peer-secret>`), iv = `<random>`
      * access secret proof expiry - expiry time of the access secret proof
  * Signed by requesting peer

### Security Considerations

The server must verify the server find secret proof is correct according to the information provided in the public peer file of the registered peer being contacted. At this point the one time key should be verified that it has only been seen this one time.

The "peer secret encrypted" is encrypted using the public key of the peer being contacted. Any information encrypted using this key can only be considered valid to/from the requesting peer only if the signature on the proof bundle has been validated by the peer being contacted. Otherwise, it's possible a compromised server could have compromised the "peer secret encrypted" by substituting another encrypted key in its place.

Since the peer being contact doesn't necessarily know the public key of the requesting peer in advanced, the information that is encrypted must be limited to the candidate passwords returned, which at worse can cause the peer being contacted to connect with a malicious peer. However, once the "Peer Identify Request" completes, the contacted peer can validate the requesting peer's find proof bundle at that time.

The peer being contacted will use the "peer secret encrypted" to decrypt the requesting peer's candidate's "password encrypted" and encrypt candidate's passwords in return but cannot assume any channel formed is in fact going to the correct peer until verified.

### Example

    {
      "request": {
        "$domain": "domain.com",
        "$appid": "xyz123",
        "$id": "abc123",
        "$handler": "peer-finder",
        "$method": "peer-location-find",
    
        "findProofBundle" : {
          "findProof": {
            "$id": "d53255d06a17778b88501f570301e7621c5a7bc4",
    
            "nonce": "7a95ff1f51923ae6e18cdb07aee14f9136afcb9c",
    
            "find": "peer://domain.com/900c9cb1aeb816da4bdf58a972693fce20e",
            "findSecretProof": "85d2f8f2b20e55de0f9642d3f14483567c1971d3",
            "findSecretProofExpires": 9484848,
    
            "context": "3b5db5880803d91f2ba9ca522c558fd1c545c28e",
            "peerSecretEncrypted": "ODVkMmY4ZjJiMjBlNTVkZ...0MmQzZjE0NDgzNTY3YzE5NzFkMw==",
    
            "iceUsernameFrag": "b92f7c1f6285d230796bb89bca57bcf9",
            "icePasswordEncrypted": "497787ddfd19843eb04479d67198010e:NDk3Nzg3...ZWIwNDQ3OWQ2NzE5ODAxMGU=",
    
            "location": {
              "$id": "5a693555913da634c0b03139ec198bb8bad485ee",
              "contact": "peer://domain.com/541244886de66987ba30cf8d19544b7a12754042",
              "details": {
                "device": { "$id": "e31fcab6582823b862b646980e2b5f4efad75c69" },
                "ip": "28.123.121.12",
                "userAgent": "hookflash/1.0.1001a (iOS/iPad)",
                "os": "iOS v4.3.5",
                "system": "iPad v2",
                "host": "foobar"
              },
              "candidates": {
                "candidate": [
                  {
                    "namespace": "http://meta.openpeer.org/candidate/finder-relay",
                    "transport": "multiplexed-json-mls/tcp",
                    "type": "relay",
                    "host": "100.200.10.20",
                    "port": 32113,
                    "accessToken": "9d934822ccca53ac6e16e279830f4ffe3cfe1d0e",
                    "accessSecretProofEncrypted": "8b29fe4c606e370df6704ed0abb4e2b2:U0RQIHN1Y2t...zIHJlbGFseSBiYWQ="
                  }
                  {
                    "namespace": "http://meta.openpeer.org/candidate/ice",
                    "transport": "json-mls/rudp",
                    "type": "srflx",
                    "foundation": "2130706431",
                    "ip": "100.200.10.20",
                    "port": 9549,
                    "priority": 43843,
                    "related": {
                      "ip": "192.168.10.10",
                      "port": 32932
                    }
                  },
                  {
                    "namespace": "http://meta.openpeer.org/candidate/ice",
                    "transport": "json-mls/rudp",
                    "type": "host",
                    "foundation": "1694498815",
                    "ip": "192.168.10.10",
                    "port": 19597,
                    "priority": 32932
                  }
                ]
              }
            }
          },
          "signature": {
            "reference": "#d53255d06a17778b88501f570301e7621c5a7bc4",
            "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
            "digestValue": "ZDUzMjU1ZDA2YTE...NjIxYzVhN2JjNA==",
            "digestSigned": "WkRVek...TNelZoTjJKak5BPT0=",
            "key": { "uri": "peer://domain.com/541244886de66987ba30cf8d19544b7a12754042" }
          }
        },
    
        "exclude": {
          "locations": {
            "location": [
              { "$id": "c52591f27deab5cd48bc515e61a3df4d" },
              { "$id": "59d090f7fdd43a2a59beb2018609e2f2" }
            ]
          }
        }
      }
    }


Peer Location Find Result (B)
-----------------------------

### Purpose

This is the result to the request and it returns a list of locations that the peer finder will attempt to contact.

### Outputs

  * List of locations being searched
  * Additional information about the locations (as applicable)
  * Signed by finder private key and signature key referenced by fingerprint of finder's public key

### Security Considerations

Since the request was successfully issued, the information contained in the details section of the Peer Location Register Request of the peer being contacted is returned to the requester. The requester will then know how many locations will be contacted and where to expect a notification reply.

### Example

    {
      "result": {
        "$domain": "domain.com",
        "$appid": "xyz123",
        "$id": "abc123",
        "$handler": "peer-finder",
        "$method": "peer-location-find",
        "$timestamp": 13494934,
    
        "serverFindProofBundle": {
          "serverFindProof": {
            "$id": "76bda29cbef7b810c464a5dfd68e41bc",
    
            "locations": {
              "location": [
                {
                  "$id": "170f5d7f6ad2293bb339e788c8f2ff6c",
                  "contact": "peer://domain.com/900c9cb1aeb816da4bdf58a972693fce20e",
                  "details": {
                    "device": { "$id": "e31fcab6582823b862b646980e2b5f4efad75c69" },
                    "ip": "28.123.121.12",
                    "userAgent": "hookflash/1.0.1001a (iOS/iPad)",
                    "os": "iOS v4.3.5",
                    "system": "iPad v2",
                    "host": "foobar"
                  }
                },
                {
                  "$id": "5a693555913da634c0b03139ec198bb8bad485ee",
                  ...
                }
              ]
            }
          },
          "signature": {
            "reference": "#76bda29cbef7b810c464a5dfd68e41bc",
            "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
            "digestValue": "TlRSbVpEUm1OakJ...LnhNamRtWVdRNE9EazBNUT09",
            "digestSigned": "VGxSU2JWcEVVbTFP....hUzR1TG5oTmFtUnRXVmRSTkU5RWF6Qk5VVDA5",
            "key": { "fingerprint": "54fd4f60cbbbf0077ec33c6447497127fad88941" }
          }
        }
      }
    }


Peer Location Find Request (C)
------------------------------

### Purpose

This request is forwarded from the requesting peer's finder to the replying peer's finder.

### Inputs

  * Same information as Peer Location Find Request (A)

### Security Considerations

Application ID should be stripped before forwarding this request.

### Example

    {
      "request": {
        "$domain": "domain.com",
        "$id": "abc123",
        "$handler": "peer-finder",
        "$method": "peer-location-find",
    
        "findProofBundle" : {
          ...
        }
      }
    }


Peer Location Find Request (D)
------------------------------

### Purpose

This request is forwarded from the replying peer's finder to the replying peer.

### Inputs

  * Same information as Peer Location Find Request (A)

### Security Consideration

### Example

    {
      "request": {
        "$domain": "domain.com",
        "$id": "abc123",
        "$handler": "peer-finder",
        "$method": "peer-location-find",
    
        "findProofBundle" : {
          ...
        }
      }
    }


Peer Location Find Reply Notification (E)
-----------------------------------------

### Purpose

This reply notification is sent directly from the replying peer to the requesting peer's finder (by the replying peer creating a direct connection from the replying peer to the requesting peer's finder and using the relay credentials to create a "channel-map" with the requesting peer).

### Outputs

  * Digest value from signature sent in original request - the reply location might not have the ability to validate the signature of the request but the reply location must validate the signature's hash value is correct and copy this value back to the original requester bundled in its own signed package (since the requester knows the original value and must have the public peer file of the reply location to validate the reply's bundle). This allows the requester to validate the original request remained non-tampered throughout and ignore replies where tampering might have occurred.
  * Context - this identifier is combined with the remote peer's context to form the "requester" / "reply" context ID pairing for MLS
  * Peer secret - this key passphrase is the password used to encrypt data in the reverse direction (as it's sent over MLS directly to the receiving peer there's no need to encrypt it)
  * ICE username frag - the username fragment for ICE negotiation
  * ICE password - the password passphrase for ICE negotiation
  * Location details
    * Location ID of requesting location
    * Contact ID of requesting location
    * Location details
  * Location candidate contact addresses for peer location, each containing:
    * transport
    * if class is "ice":
      * transport
      * type - "host" or "srflx" or "prflx" or "relay"
      * IP
      * port
      * priority
      * related IP (optional, mandatory if type is "srflx" or "prflx" or "relay")
      * related port (optional)
  * Signed by replying peer

### Security Considerations

This request must be sent over a secure channel with MLS.

### Example

    {
      "notify": {
        "$domain": "domain.com",
        "$appid": "xyz123",
        "$id": "abc123",
        "$handler": "peer-finder",
        "$method": "peer-location-find",
        "$timestamp": 4344333232,
    
        "findProofBundle" : {
          "findProof": {
            "requestFindProofBundleDigestValue": "ZDUzMjU1ZDA2YTE...NjIxYzVhN2JjNA==",
    
            "context": "a497f346db82ae34c2d9b7f62e34b9757d211bef",
            "peerSecret": "402a95986e81cfacb1d0668f240713f4ca556d73",
    
            "iceUsernameFrag": "219d07d37faee86a5a866ff3e363b790b3b98fbb",
            "icePassword": "ed84448d05fde7f6b12442df3d07e169583226b4",
    
            "final": false,
    
            "location": {
              "$id": "1f77425b06b33bfc1d9932a0716f3f2c92ec0e5",
              "contact": "peer://domain.com/541244886de66987ba30cf8d19544b7a12754042",
              "details": {
                "device": { "$id": "e31fcab6582823b862b646980e2b5f4efad75c69" },
                "ip": "100.200.10.20",
                "userAgent": "hookflash/1.0.1001a (iOS/iPad)",
                "os": "iOS v4.3.5",
                "system": "iPad v2",
                "host": "smartie"
              },
              "candidates": {
                "candidate": [
                  {
                    "namespace": "http://meta.openpeer.org/candidate/ice",
                    "transport": "json-mls/rudp",
                    "type": "srflx",
                    "foundation": "2130706431",
                    "ip": "100.200.10.20",
                    "port": 9549,
                    "priority": 4388438,
                    "related": {
                      "ip": "192.168.10.10",
                      "port": 32932
                    }
                  },
                  {
                    "namespace": "http://meta.openpeer.org/candidate/ice",
                    "transport": "json-mls/rudp",
                    "type": "host",
                    "foundation": "1694498815",
                    "ip": "192.168.10.10",
                    "port": 19597,
                    "priority": 43923293
                  }
                ]
              }
            }
          },
          "signature": {
            "reference": "#d53255d06a17778b88501f570301e7621c5a7bc4",
            "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
            "digestValue": "ZDUzMjU1ZDA2YTE...NjIxYzVhN2JjNA==",
            "digestSigned": "WkRVek...TNelZoTjJKak5BPT0=",
            "key": { "uri": "peer://domain.com/541244886de66987ba30cf8d19544b7a12754042" }
          }
        }
      }
    }



Peer Location Find Reply Notification (F)
-----------------------------------------

### Purpose

This reply is forwarded from the requesting peer's finder to the requesting peer.

### Outputs

  * Same information as Peer Location Find Reply (E)

### Security Considerations

This request must be sent over a secure channel with MLS.

### Example

    {
      "notify": {
        "$domain": "domain.com",
        "$appid": "xyz123",
        "$id": "abc123",
        "$handler": "peer-finder",
        "$method": "peer-location-find",
        "$timestamp": 4344333232,
    
        "findProofBundle" : {
          ...
        }
      }
    }



Peer Location Find Request (single point to multipoint)
-------------------------------------------------------

### Request Flow

![Peer Location Find Request Flow](PeerLocationFindRequestFlow2.png)

The request is identical to "single point to single point" except the request would fork to the two Finders responsible for the two different locations of "bob@bar.com". While above shows one request fork completing before the other request fork begins, in reality the requests would fork simultaneously. Given that another location exists for "bob@bar.com", the request start out identical but the routes would diverge and the resulting reply would be complete different.

For the sake of simplicity, Peer Location Find Request/Reply A-F are not repeated.

Peer Location Find Request (G)
------------------------------

### Purpose

This request is forked and sent to the alternate replying peer's finder.

### Inputs

  * Same information as Peer Location Find Request (A)

### Security Considerations

Same as Peer Location Find Request (C)

### Example

    {
      "request": {
        "$domain": "domain.com",
        "$id": "abc123",
        "$handler": "peer-finder",
        "$method": "peer-location-find",
    
        "findProofBundle" : {
          ...
        }
      }
    }


Peer Location Find Request (H)
------------------------------

### Purpose

This request is sent from the alternate replying peer's finder to the alternate replying peer.

### Inputs

  * Same information as Peer Location Find Request (A)

### Security Considerations

Same as Peer Location Find Request (D)

### Example

    {
      "request": {
        "$domain": "domain.com",
        "$id": "abc123",
        "$handler": "peer-finder",
        "$method": "peer-location-find",
    
        "findProofBundle" : {
          ...
        }
      }
    }


Peer Location Find Reply Notification (I)
-----------------------------------------

### Purpose

This reply is sent directly from the alternative replying peer to the requesting peer's finder (by the alternative replying peer creating a direct connection from the alternative replying peer to the requesting peer's finder). This looks very much like Peer Location Find Reply (E) except the identifiers would be completely different.

### Outputs

  * Same information as applicable in Peer Location Find Reply (E) but with different values as generated from the alternative location.

### Security Considerations

Same as Peer Location Find Reply (E)

### Example

    {
      "notify": {
        "$domain": "domain.com",
        "$id": "abc123",
        "$handler": "peer-finder",
        "$method": "peer-location-find",
        "$timestamp": 4344333232,
    
        "findProofBundle" : {
          "findProof": {
            "$id": "d53255d06a17778b88501f570301e7621c5a7bc4",
    
            "context": "a9a68a09f904611efd91e245e8e62ab836f757dc",
            "peerSecret": "e0ff7c2fcd42202e2fa3d93029f829157db7cd7e",
    
            "requestFindProofBundleDigestValue": "ZDUzMjU1ZDA2YTE...NjIxYzVhN2JjNA==",
    
            "location": {
              "$id": "d0866fe404867a94949771bfd606f68c3c3c5bd1",
              "contact": "peer://domain.com/541244886de66987ba30cf8d19544b7a12754042",
              "details": {
                "device": { "$id": "54700644c8ce4c663457c7433d6b49ed" },
                "ip": "75.43.32.12",
                "userAgent": "hookflash/1.0.1001a (iOS/iPad)",
                "os": "iOS v4.3.5",
                "system": "iPad v2",
                "host": "foobie"
              },
              "candidates": {
                "candidate": [
                  {
                    "namespace": "http://meta.openpeer.org/candidate/ice",
                    "transport": "json-mls/rudp",
                    "foundation": "43848384",
                    "ip": "75.43.32.12",
                    "port": 43432,
                    "priority": 39932,
                    "related": {
                      "ip": "192.168.10.200",
                      "port": 32932
                    }
                  },
                  {
                    "namespace": "http://meta.openpeer.org/candidate/ice",
                    "transport": "json-mls/rudp",
                    "foundation": "43243242",
                    "ip": "192.168.10.200",
                    "port": 20574,
                    "priority": 488323
                  }
                ]
              }
            }
          },
          "signature": {
            "reference": "#d53255d06a17778b88501f570301e7621c5a7bc4",
            "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
            "digestValue": "ZDUzMjU1ZDA2YTE...NjIxYzVhN2JjNA==",
            "digestSigned": "WkRVek...TNelZoTjJKak5BPT0=",
            "key": { "uri": "peer://domain.com/541244886de66987ba30cf8d19544b7a12754042" }
          }
        }
      }
    }


Peer Location Find Reply Notification (J)
-----------------------------------------

### Purpose

This is the forwarded reply from the requesting peer's finder to the requesting peer.

### Outputs

  * Same information as Peer Location Find Reply (I)
 
### Security Considerations

Same as Peer Location Find Reply Notification (F)

### Example

    {
      "notify": {
        "$id": "abc123",
        "$handler": "peer-finder",
        "$method": "peer-location-find",
        "$timestamp": 4344333232,
    
        "findProofBundle" : {
          ...
        }
    
      }
    }


Peer To Peer Protocol
=====================

Peer Identify Request
---------------------

### Purpose

This request notifies the peer that responded to the find reply notification of the original requesting peer's identifying information. This request must be the first request sent from the peer that initiated the find request to the peer that replied to the find request.

### Inputs

  * Contact of the initiating contact peer
  * Client nonce
  * Expiry of the request - the expiry window for this short term credentials must be long enough to factor any looks-ups the replying peer might wish to perform before sending a result
  * Find secret as obtained from the Section "B" of the public peer file for the replying peer - peer should reject peer unless this is present or unless the peer is in a common conversation thread with the peer)
  * Fingerprint - the fingerprint of the certificate used by the requesting peer's transport
  * The location information of requesting peer
  * The public peer file of the requesting peer - section A at minimal
  * Signed by requesting peer's private key

### Outputs

  * Digest value - the value of the digest from the signature of the requesting peer's "peer identify proof bundle"
  * Fingerprint - the fingerprint if the certificate used by the receiving peer's transport
  * Location of the replying peer
  * Signed by replying peer's private key

### Security Considerations

The requesting peer must send this request over a secure channel.

The replying peer must validate the request in the following ways:

  * the find secret matches the find secret of it's own public peer file
  * the request has not expired
  * the nonce has not been seen before (the nonce must be remembered for a reasonable period of time, or at maximum until the expiry time of the request)
  * the finger print matches the fingerprint of the requesting peer's transport channel
  * the validity of the public peer file provided
  * the signature on the request matches the public peer file provided

The requesting peer must validate the result in the following ways:

  * the signature on the result matches the peer it requested to find
  * the digest value in the result matches the digest value from the original signature on the request
  * the fingerprint in the result matches the fingerprint of the replying's peers transport

### Example

    {
      "request": {
        "$id": "abc123",
        "$handler": "p2p",
        "$method": "peer-identify",
    
        "peerIdentityProofBundle": {
          "peerIdentityProof": {
            "$id": "ec065f4b46a22872f85f6ba5addf1e2",
    
            "nonce": "759cef14b626c9bacc9a52253fd68da29d5b6491",
            "expires": 574732832,
    
            "findSecret": "YjAwOWE2YmU4OWNlOTdkY2QxNzY1NDA5MGYy",
    
            "fingerprint": "28c5c1099f3d4c14390f046d8182748576ae17b3",
    
            "location": {
              "$id": "5c5fdfab4bbf8cc8345555172914b9733b2034a4",
              "contact": "peer://domain.com/db9e3a737c690e7cdcfbacc29e4a54dfa5356b63",
              "details": {
                "device": { "$id": "105f38b84d01e6d4bc60d1123c62c957" },
                "ip": "28.123.121.12",
                "userAgent": "hookflash/1.0.1001a (iOS/iPad)",
                "os": "iOS v4.3.5",
                "system": "iPad v2",
                "host": "foobar"
              }
            },
            "peer": {
              "sectionBundle": {
                "section": {
                  "$id": "A",
                  ...
                },
                ...
              }
            }
          },
          "signature": {
            "reference": "#ec065f4b46a22872f85f6ba5addf1e2",
            "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
            "digestValue": "ZGZrbnNua2...pmZXdraiBlYnJlcnJmZXJl",
            "digestSigned": "WkdacmJuTnVhMnBtWl...mFpQmxZbkpsY25KbVpYSmw=",
            "key": { "uri": "peer://example.com/db9e3a737c690e7cdcfbacc29e4a54dfa5356b63" }
          }
        }
      }
    }
.

    {
      "result": {
        "$id": "abc123",
        "$handler": "p2p",
        "$method": "peer-identify",
        "$timestamp": 43848328432,
    
        "peerIdentityProofBundle": {
          "peerIdentityProof": {
            "$id": "8c905668ddb739b05c66734ffa6e46073c3d4a27",
    
            "digest": "ZGZrbnNua2...pmZXdraiBlYnJlcnJmZXJl",
    
            "fingerprint": "31e450e5f094e464f21b668102974e027010c8a7",
     
            "location": {
              "$id": "9e02827c0f43c511c30bd410bacf9a83",
              "contact": "peer://domain.com/5c15749f598b9ea1f60c48adf792ed72f581f3e4",
              "details": {
                "device": { "$id": "df036bcabfb1826a2596478b0d858e4d" },
                "ip": "89.43.12.11",
                "userAgent": "hookflash/1.0.1001a (iOS/iPad)",
                "os": "iOS v6.1",
                "system": "iPad v2",
                "host": "trucker"
              }
            }
          },
          "signature": {
            "reference": "#8c905668ddb739b05c66734ffa6e46073c3d4a27",
            "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
            "digestValue": "c2RwI...HN1Y2tz",
            "digestSigned": "MyUndJSE4c2RwIHN1Y2tz...TJ0eiBjMlJ3SUhOMVkydHo=",
            "key": { "uri": "peer://example.com/d1878a88dc500bcf33a9b6b478b7d76e82b7775e" }
          }
        }
      }
    }


Peer Keep-Alive Request
-----------------------

### Purpose

This request keeps a connection alive between the peers.

### Inputs

None.

### Outputs

  * Expiry epoch (when next a keep alive must be sent by)

### Security Considerations

The client must have an established peer session to issue this request.

### Example

    {
      "request": {
        "$id": "abc123",
        "$handler": "p2p",
        "$method": "peer-keep-alive"
      }
    }
.

    {
      "result": {
        "$id": "abc123",
        "$handler": "p2p",
        "$method": "peer-keep-alive",
        "$timestamp": 13494934,
    
        "expires": 483949923
      }
    }


Document Specifications
=======================

The published document specifications are outside the scope of this particular document. Please refer to the "Open Peer Conversation Thread Specification" as a proposal for multiparty peer hosted conversations for chat, audio and video (and other media).
