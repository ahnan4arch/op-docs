Abstract
========

Open Peer allows for additional services to be layed ontop of the basic operational services. One of the needs of a good communication application is the ability to fetch a list of contacts for a particular user's identity. The Open Peer specification already allows for the lookup of identities found through some "unspecified" mechanism. This annex is one such specification on how the identities for a contact are fetched for users.

A service/identity provider is not required to support this annex but it is highly recommended for social identities.

Design Considerations
=====================

The Open Peer Specification "Annex Rolodex" has several design considerations to address:

  * Must allow the rolodex service to fetch/cache contants on behalf of an identity
  * Must allow the rolodex service to operate in a method that allows the server not to store a client's credentials
  * Must allow an identity service to send identity fetching credentials to a rolodex service without compromising those credentials
  * Must allow a client application to download deltas of changes to the contact list from a last known download point.
  * Must allow a client application to reconstruct a list of contacts from scratch should locally cached information become lost.
  * Must allow for efficient polling and/or push notifications to the client application.

Key Object Concepts
===================

### Identity Provider

Any service offering that grants Identity personas, such as Facebook, LinkedIn, Twitter or other 3rd parties that offer their own Identities.

### Rolodex Service

A service allowing the efficient fetching and caching of address box of contact information on behalf of client applications.


Identity Service Requests (Annex)
=================================

Identity Access Rolodex Credentials Get Request
-----------------------------------------------

### Purpose

This request is sent from the outerframe to the inner frame to fetch identity credentials for use with the rolodex service.

### Inputs

None.

### Returns

  * Rolodex server token - the access token to be used with the rolodex service. The server must ensure the token has a sufficient validity timeframe left for the rolodex service before returning to the client.

### Security Considerations

As this request is optional, the client can detect if this request is available prior to sending by detecting if the "rolodex" service is available via the "Bootstrapper Service Requests -> Services Get Request". If the rolodex is listed for the identity provider's Bootstrapper Service then this request is allowed to be sent to the identity provider as part of the "Identity Access" sequence between the outer/inner frame messaging.

The exact meaning of the rolodex server token is arbitrary between the identity service and the rolodex service but the client should be unable to decode any secret server information from the token and it may be encrypted.

### Example

    {
      "request": {
        "$domain": "provider.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "identity",
        "$method": "identity-access-rolodex-credentials-get"
      }
    }

    {
      "result": {
        "$domain": "provider.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "identity",
        "$method": "identity-access-rolodex-credentials-get",
        "$timestamp": 439439493,
    
        "rolodex": {
           "serverToken": "b3ff46bae8cacd1e572ee5e158bcb04ed9297f20-9619e3bc-4cd41c9c64ab2ed2a03b45ace82c546d"
         }
    
      }
    }

Rolodex Service Requests
========================

Rolodex Access Request
----------------------

### Purpose

This request is sent by the client application to get access to the rolodex service.

### Inputs

  * Client nonce - a onetime use nonce, i.e. cryptographically random string
  * Identity information
    * Identity access token - as returned from the "identity access complete" request
    * Proof of 'identity access secret' - proof required to validate that the 'identity access secret' is known, proof = hmac(`<identity-access-secret>`, "identity-access-validate:" + `<identity>` + ":" + `<client-nonce>` + ":" + `<expires>` + ":" + `<identity-access-token>` + ":rolodex-access")
    * Expiry of the proof for the 'identity access secret' - a window in which access secret proof is considered valid
    * Original identity URI
    * Identity provider (optional, required if identity does not include domain or if domain providing identity service is different)
  * Rolodex information
    * server token - given by the identity service that only has meaning to the rolodex service
    * refresh - request the contact list be refreshed immediately
    * version - (optional) a version string as previously returned from the rolodex update representing the delta information last obtained from the rolodex service (only specify if previously known)
  * Grant information
    * grant ID - the grant ID that has been given namespace access to the rolodex namespace, i.e. "https://openpeer.org/permission/rolodex"

### Returns

  * Rolodex information
    * rolodex access key - a key to access the rolodex service
    * rolodex access secret - a secret for use to access the rolodex service
    * rolodex access secret expires - when the access secret will expire and no longer be valid
    * update next - the timestamp when the next update can/should be issued (but not before)

### Security Considerations

The rolodex service must validate the grant ID with the grant service and must validate the identity access with the identity service.

### Example

    {
      "request": {
        "$domain": "provider.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "rolodex",
        "$method": "rolodex-access",
    
        "clientNonce": "ed585021eec72de8634ed1a5e24c66c2",
        "identity": {
          "accessToken": "a913c2c3314ce71aee554986204a349b",
          "accessSecretProof": "b7277a5e49b3f5ffa9a8cb1feb86125f75511988",
          "accessSecretProofExpires": 43843298934,
    
          "uri": "identity://domain.com/alice",
          "provider": "domain.com"
        },
    
        "rolodex": {
           "serverToken": "b3ff46bae8cacd1e572ee5e158bcb04ed9297f20-9619e3bc-4cd41c9c64ab2ed2a03b45ace82c546d",
           "refresh": false,
           "version": "4341443-54343a"
         },
    
         "grant": {
           "$id": "e8eed01c9fc288bf35b54d8c78081663ff921d74"
         }
    
      }
    }

    {
      "result": {
        "$domain": "provider.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "rolodex",
        "$method": "rolodex-access",
        "$timestamp": 439439493,
    
        "rolodex": {
          "accessToken": "91c4d836e216139f6fe4d417ca19afe78bab87d2",
          "accessSecret": "943ec6e93c71591d3ee43464059b25ecd6312a07",
          "accessSecretExpires": 5848443,
          "updateNext": 54433434
        }
      }
    }

Rolodex Update Request
----------------------

### Purpose

This request is sent by the client application to get access to the rolodex service.

### Inputs

  * Client nonce - a onetime use nonce, i.e. cryptographically random string
  * rolodex information
    * server token - given by the identity service that only has meaning to the rolodex service
    * rolodex access token - as returned from the "rolodex access" request
    * Proof of 'rolodex access secret' - proof required to validate that the 'identity access secret' is known, proof = hmac(`<rolodex-access-secret>`, "rolodex-access-validate:" + ":" + `<client-nonce>` + ":" + `<expires>` + ":" + `<rolodex-access-token>` + ":rolodex-update")
    * Expiry of the proof for the 'rolodex access secret' - a window in which access secret proof is considered valid
    * refresh - request the contact list be refreshed immediately
    * version - a version string as previously returned from the rolodex update request representing the delta information last obtained from the rolodex service
  * Grant information
    * grant ID - the grant ID that has been given namespace access to the rolodex namespace, i.e. "https://openpeer.org/permission/rolodex"

### Returns

  * Rolodex information
    * update next - the timestamp when the next update can/should be issued (but not before)
    * version - a version string representing the delta information from last update to this update for the rolodex service
  * list of identities, with each identity containing:
    * disposition - "update" or "remove"
    * Original identity URI
    * Provider - service responsible for this identity
    * Identity display name - (optional), the display name to use with the identity
    * Identity rendered public profile URL - (optional), a webpage that can be rendered by the browser to display profile information about this identity
    * Programmatic public profile URL - (optional), a machine readable vcard like webpage that can be used to extract out common profile information
    * Public Feed URL - (optional), an RSS style feed representing the public activity for the user
    * Optional list of avatars containing:
      * Avatar name - (optional), name representing subject name of avatar (note: avatars with the same name are considered identical and thus are used to distinguish between varying sizes for the same avatar)
      * Avatar URL - URLs to download the avatar(s) associated with the identity
      * Avatar pixel width - (optional), pixel width of the avatar image
      * Avatar pixel height - (optional), pixel height of avatar image

### Security Considerations

The rolodex can control the rate in which identities are returned to the client application by giving contacts over time and letting the client application refetch new contacts only when the next suggested update should occur. The version string allows the rolodex to return the delta information for contacts from the last update point to ensure clients do not have to fetch contacts needlessly.

The rolodex will not know the state of the identity with regards to its association to a peer file or a lockbox. The "Identity Lookup Service" must be used to obtain that type of information and must be considered more authoritative over the information obtained from the rolodex service.

The information returned from update of a previously returned identity must take priority over previous information for the same identity.

If the result is an error result with error code "424" i.e. "Failed Rolodex Token Dependency" then the rolodex access token must be refreshed via the identity service.

### Example

    {
      "request": {
        "$domain": "provider.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "rolodex",
        "$method": "rolodex-update",
    
        "clientNonce": "ed585021eec72de8634ed1a5e24c66c2",
        "rolodex": {
           "serverToken": "b3ff46bae8cacd1e572ee5e158bcb04ed9297f20-9619e3bc-4cd41c9c64ab2ed2a03b45ace82c546d",
           "accessToken": "a913c2c3314ce71aee554986204a349b",
           "accessSecretProof": "b7277a5e49b3f5ffa9a8cb1feb86125f75511988",
           "accessSecretProofExpires": 43843298934,
           "refresh": false,
           "version": "4341443-54343a"
         }
    
      }
    }

    {
      "result": {
        "$domain": "provider.com",
        "$appid": "xyz123",
        "$id": "abd23",
        "$handler": "rolodex",
        "$method": "rolodex-update",
        "$timestamp": 439439493,
    
        "rolodex": {
          "updateNext": 54433434
           "version": "4341443-54343a"
         },
    
         "identities": {
           "identity": [
             {
               "$disposition": "update",
               "uri": "identity://foo.com/alice",
               "provider": "foo.com",
    
               "name": "Alice Applegate",
               "profile": "http://domain.com/user/alice/profile",
               "vprofile": "http://domain.com/user/alice/vcard",
               "feed": "http://domain.com/user/alice/feed",
               "avatars": {
                 "avatar": { "url": "http://domain.com/user/alice/p" }
               }
             },
             {
               "$disposition": "remove",
               "uri": "identity://foo.com/bob",
               "provider": "foo.com"
             }
           ]
         }
      }
    }

