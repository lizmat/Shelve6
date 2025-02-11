[![Actions Status](https://github.com/lizmat/Shelved/workflows/test/badge.svg)](https://github.com/lizmat/Shelved/actions)

NAME
====

Shelved

DESCRIPTION
===========

An artifact repository for the Raku Programming Language and friends

The goal is to build a artifact repository service that Raku modules, but also other stuff, can be pushed to and pulled via the usual means (i.e. pushed from CI or manual workflows, pulled via `zef`). This would be useful for an organisation doing Raku development, does not want all their code publicly available, yet want to use a regular module-centric, tarball/release-based development flow.

Essentially this is a "content storage" service as described in [S22](https://design.raku.org/S22.html#content_storage).

FEATURES
========

  * Upload Raku modules

  * Fetch with zef

  * Authentication

  * Multiple configurable logical repos

Upcoming and ToDo
=================

  * cucumis sextus tests

  * adress already in use error handling/reporting

  * UI to browse and manage

  * API to manage and automate

  * Local cache/proxy for other repositories, like CPAN. Could be just a cache, or a fetch-ahead full copy. Perhaps both, configurably.

  * Rarification/expiry of artifacts in configured repositories

  * Web hooks for automation

  * Verification and other plugins

  * Shared file store, multiple shelved instances. Or a database as a store.

  * More auth types

  * Full-blown monitoring, resilience etc

  * More metadata, like when uploaded and by whom. "on-behalf" in upload script so that a CI or automation job can say on whose command they uploaded

Also grep for the `XXX` fixmes in the code!

USAGE
=====

Shelved comes as a web service that you can just start e.g. directly from the checked-out source repository via `RAKUDOLIB=lib bin/shelved`, or if it is properly installed just via `shelved`. It reads a config.yaml file, a simple sample is included, and might look like this:

```yaml
    server:
        port: 8080
        base-url: "http://localhost:8080"
    store:
        basedir: store
    repositories:
        - name: p6repo
```

  * base-url

is where you want the service to be found externally.

  * port

is of course the port the service listens on, note that it currently only binds to the first localhost interface, let me know if that gives you grief.

  * basedir

is a directory where shleve6 will store the artifacts.

  * repositories

is a list of logical artifact repositories in which you can store modules.

With the service running, you can use the supplied shelved-upload script to put artifacts into shelved:

    bin/shelved-upload raku-foo-bar-0.1.tar.gz http://localhost:8080/repos/p6repo

This script is just a thin wrapper around `curl`, you just need a multipart form post really.

In order to fetch artifacts, you need to configure your `zef` to recognise the repository. In my case I have a `~/.config/zef/config.json`, where in the `Repository` section I added:

```json
    {
        "short-name" : "shelved",
        "enabled" : 1,
        "module" : "Zef::Repository::Ecosystems",
        "options" : {
            "name" : "shelved",
            "auto-update" : 1,
            "mirrors" : [
                "http://localhost:8080/repos/p6repo/packages.json"
            ]
        }
    },
```

After that, `zef` happily pulls from shelved!

AUTHENTICATION / AUTHORIZATION
==============================

If you want to use the repository for private code, it may be a good idea to enable some security on it. Shelved can use credentials in the request and map them to a set of roles associated with that credential. Currently the only credential type supported are 'opaque' tokens, these are just striings that are not looked into (so not JWT or so). These come in a HTTP header like `Authorization: Bearer supersecret`, where 'supersecret' is the credential. In the future more credential types can be supported. To configure the mapping of credentials to roles, extend the 'server' part of the configuration:

```yaml
server:
    port: 8080
    base-url: "http://localhost:8080"
    authentication:
        opaque-tokens:
            - token: supersecret
              roles: [CI]
              owner: raku-ci-1
            - token: eng8ahquia2kungeitaequie
              roles: [DEV, ADMIN]
              owner: Max Mustermann <mmustermann@megacorp
```

In order to actually require any roles, you need to configure which roles allow what operation, on the repository:

```yaml
repositories:
    - name: p6repo
      authorization:
        upload: [CI, DEV, ADMIN]
        download: [CI, DEV, ADMIN]
        delete: [ADMIN]
```

Note that the credential is associated with all the roles from the server config, but any role in the repository section is sufficient for access to be granted. For example the credential 'eng8ahquia2kungeitaequie' above gives both the 'DEV' and the 'ADMIN' roles, any of which would be enough to upload and download artifacts.

The `shelved-upload` script supports setting these tokens through a commandline argument or an environment variable.

In order to enable `zef` to provide credentials during module fetching, you need to install the `Zef::Service::AuthenticatedDownload` plugin:

        zef install Zef::Service::AuthenticatedDownload

And configure it. The `zef` README explains where you can find the zef config, where you can add the plugin and configure it, which is best done before the other web fetchers to avoid them trying to download and failing due to auth:

```yaml
        {
            "short-name" : "authenticated-download",
            "module" : "Zef::Service::AuthenticatedDownload",
            "options" : {
                "configured-hosts" : [
                    {
                        "hostname" : "localhost",
                        "auth-type" : "opaque-token",
                        "token" :  "supersecret"
                    }
                ]
            }
        },
```

This will make zef use the configured credential for the host in question. If you do not want to put the credential into the config file, you can also leave it out and supply it via the `ZEF_AUTH_OPAQUE_TOKEN` environment variable.

AUTHORS
=======

Robert Lemmen (2018-2020), Elizabeth Mattijsen <liz@raku.rocks> (2021-)

Originally developed as `Shelve6` by Robert Lemmen, maintenance taken over and renamed to `Shelved` by Elizabeth Mattijsen. The rename was deemed to make sense in the context of the Raku Programming Language (which has no special meaning for the number 6) and the fact that this module usually runs as a daemon (hence the "d" at the end).

Source can be located at: https://github.com/lizmat/Shelved . Comments and Pull Requests are welcome.

COPYRIGHT AND LICENSE
=====================

Copyright 2018-2020 Robert Lemmen, 2021 Elizabeth Mattijsen

This library is free software; you can redistribute it and/or modify it under the Artistic License 2.0.

