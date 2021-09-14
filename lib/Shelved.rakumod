use Cro::HTTP::Router:ver<0.8.6>;
use Cro::HTTP::Server:ver<0.8.6>;
use Cro::HTTP::Response:ver<0.8.6>;
use JSON::Fast:ver<0.16>;
use YAMLish:ver<0.0.6>;

my sub load-config($filename) is export {
    try {
        die "no such file" if not $filename.IO.e;

        given $filename {
            when .ends-with(".yml") || .ends-with(".yaml") {
                return load-yaml(slurp $filename);
            }
            when .ends-with(".json") {
                return from-json(slurp $filename);
            }
            default {
                die "unsupported file format, can do yaml and json";
            }
        }
    }
    die "Failed to read config file '$filename': {$!.Str}" if $!;
}

class X::Shelved::ClientError is Exception {
    has $.code;
    has $.message;
}

class Shelved:ver<0.3.0>:auth<zef:lizmat> {

    class AuthInfo {
        has $.owner;
        has @.roles;
    }

    class Logging {
        has $.ctx;

        my $max-ctx-width = 0;

        my $date-fmt = sub ($self) {
            given $self {
                sprintf "%04d-%02d-%02d %02d:%02d:%06.3f",
                    .year, .month, .day,
                    .hour, .minute, .second
            }
        }

        my sub log($severity, $ctx, $msg --> Nil) {
            say   DateTime.now(formatter => $date-fmt)
                ~ " ["
                ~ sprintf('%-' ~ $max-ctx-width ~ 's', $ctx)
                ~ "] ["
                ~ sprintf('%-5s', $severity) ~ "] $msg";
            $*OUT.flush;
        }

        method new($ctx) {
            if ($ctx.chars > $max-ctx-width) {
                $max-ctx-width = $ctx.chars;
            }
            self.bless(ctx => $ctx)
        }

        method trace($msg) { log('trace', $!ctx, $msg) }
        method debug($msg) { log('debug', $!ctx, $msg) }
        method info($msg)  { log('info', $!ctx, $msg)  }
        method warn($msg)  { log('warn', $!ctx, $msg)  }
        method error($msg) { log('error', $!ctx, $msg) }
    }

    class Repository {
        has $.name;
        has $.authorization;
        has $.base-url;
        has $.server;
        has $.store;

        my $log = Shelved::Logging.new('repo');

        method start() {
            $!base-url = $!server.base-url;
            $log.debug("Setting up repository '$!name', reachable under '$!base-url/repos/$!name'");
            $!server.register-repo($!name, self);
            for ('upload', 'download') -> $perm {
                my $roles = $!authorization{$perm} // ();
                if not $roles {
                    $log.warn("No roles are required to '$perm' to $!name, this feels unsafe");
                }
            }
        }

        method stop() { }

        method !require-permission($perm, $auth-info) {
            my $sufficient-roles = set @($!authorization{$perm} // ());
            my $present-roles = set ();
            my $owner-name = "unknown client";
            if $auth-info {
                $present-roles = set $auth-info.roles;
                $owner-name = $auth-info.owner;
            }

            if $sufficient-roles {
                if not $sufficient-roles (&) $present-roles {
                    $log.debug("Denying $perm access on repo $!name to $owner-name");
                    die X::Shelved::ClientError.new(code => 403,
                        message => "Denying $perm access, not authorized");
                }
            }
        }

        method put-file($filename, $blob, $auth-info) {
            self!require-permission("upload", $auth-info);
            # a bit primitive, but there you go for now
            my $proc = run(<tar --list -z -f - >, :out, :in);
            $proc.in.write($blob);
            $proc.in.close;
            my $out = $proc.out.slurp-rest();
            my $meta-membername;
            for $out.lines -> $l {
                # XXX ends-with? should be complete match
                if $l.ends-with('META6.json') || $l.ends-with('META6.info') {
                    $meta-membername = $l;
                }
            }
            if ! defined $meta-membername {
                my $msg = "Artifact '$filename' seems to not contain a META6.json or .info, refusing";
                $log.warn($msg);
                # XXX is 403 the right code?
                die X::Shelved::ClientError.new(code => 403, message => $msg);
            }

            $proc = run(qqw{tar --get --to-stdout -z -f - $meta-membername}, :out, :in);
            $proc.in.write($blob);
            $proc.in.close;
            my $meta-json = $proc.out.slurp-rest();
            try {
                my $parsed = from-json($meta-json);
                # XXX in the future also perform pluggable checks on it
            }
            if $! {
                my $msg = "Artifact '$filename' has malformed metadata, refusing";
                $log.warn($msg);
                # XXX is 403 the right code?
                die X::Shelved::ClientError.new(code => 403, message => $msg);
            }
            $!store.put($!name, $filename, $blob, $meta-json);
        }

        method get-package-list($auth-info) {
            self!require-permission("download", $auth-info);
            # XXX cache the list?
            my $packages = $!store.list-artifacts($!name);
            my @result-list;
            for $packages -> $p {
                my $meta-json = $!store.get-meta($!name, $p);
                my $meta = from-json($meta-json);
                $meta{"source-url"} = "$!base-url/repos/$!name/$p";
                @result-list.push($meta);
            }
            $log.debug("fetch of package list from repo '$!name' with {@result-list.elems} entries");
            @result-list
        }

        method get-file($fname, $auth-info) {
            self!require-permission("download", $auth-info);
            if $!store.artifact-exists($!name, $fname) {
                $log.debug("fetch of artifact '$fname' from repo '$!name'");
                $fname
            }
            else {
                $log.debug("attempt to fetch non-existing artifact '$fname' from repo '$!name'");
                Nil
            }
        }
    }

    class Server {
        has $.port;
        has $.base-url;
        has $.authentication;
        has $!http-service;
        has %!repositories;

        my $log = Shelved::Logging.new('server');

        my class AuthTokenToRolesResolver does Cro::HTTP::Middleware::Request {
            has $.authentication;
            method process(Supply $requests --> Supply) {
                supply whenever $requests -> $request {
                    my $auth-header = $request.header('Authorization')//'';
                    if $auth-header ~~ /^ 'Bearer ' $<token>=[\w+] $/ {
                        for @($!authentication<opaque-tokens>) -> $token-config {
                            if $token-config<token> eq $<token> {
                                $request.auth = Shelved::AuthInfo.new(
                                    owner => $token-config<owner>,
                                    roles => @($token-config<roles>));
                                last;
                            }
                        }
                    }
                    emit $request;
                }
            }
        }

        method register-repo($name, $repo) {
            %!repositories{$name} = $repo;
        }

        # this wraps a route handler block and adds logic to convert exceptions
        # to error responses
        sub with-api-exceptions(&route-handler) {
            &route-handler();
            CATCH {
                when X::Shelved::ClientError {
                    response.status = .code;
                    content("text/plain", .message);
                }
                default {
                    $log.warn("Unhandled exception: " ~ .message);
                    $log.warn(.backtrace);
                    response.status = 500;
                    content("text/plain", .message);
                }
            }
        }

        method start() {
            my $repo-routes = route {
                before-matched AuthTokenToRolesResolver.new(:$!authentication);

                get -> $repo-name {
                    redirect "/repos/$repo-name/packages.json";
                }
                get -> $repo-name, 'packages.json' {
                    with-api-exceptions({
                        if %!repositories{$repo-name}:exists {
                            content 'application/json', to-json(
                                %!repositories{$repo-name}.get-package-list(request.auth),
                                :sorted-keys);
                        }
                        else {
                            not-found;
                        }
                    })
                }
                get -> $repo-name, *@path {
                    with-api-exceptions({
                        if %!repositories{$repo-name}:exists {
                            my $path = %!repositories{$repo-name}.get-file(
                                            @path.join('/'),
                                            request.auth);
                            if defined $path {
                                # XXX configurably serve through nginx directly
                                static $path;
                            }
                            else {
                                not-found;
                            }
                        }
                        else {
                            not-found;
                        }
                    })
                }
                post -> $repo-name {
                    with-api-exceptions({
                        if %!repositories{$repo-name}:exists {
                            request-body -> $object {
                                #  make sure it is a Cro::HTTP::Body::MultiPartFormData
                                # with one entry named "artifact"
                                if ! $object ~~ Cro::HTTP::BodyParser::MultiPartFormData.WHAT {
                                    forbidden;
                                    content("text/plain", "artifact upload must be a MultiPartFormData");
                                }
                                for $object.parts -> $part {
                                    if $part.name eq 'artifact' {
                                        %!repositories{$repo-name}.put-file(
                                                $part.filename,
                                                $part.body-blob,
                                                request.auth);
                                        $log.info("upload of artifact '{$part.filename}' to $repo-name, {$part.body-blob.elems} octets");
                                    }
                                    else {
                                        forbidden;
                                        content("text/plain", "part name of upload must be 'artifact'");
                                    }
                                }
                            }
                        }
                        else {
                            not-found;
                        }
                    })
                }
            };

            my $top-router = route {
                include 'repos' => $repo-routes;
            };

            $!http-service = Cro::HTTP::Server.new(
                :host('localhost'), :port($!port), :application($top-router));
            $!http-service.start;

            $log.debug("HTTP server listening on port $!port");
        }

        method stop() {
            $!http-service.stop;
        }
    }

    class Store {
        has $.basedir;

        my $log := Shelved::Logging.new('store');

        method start() {
            $log.debug("Setting up store with file backend at '$!basedir.IO.absolute()'");
        }

        method stop() { }

        method put($path, $filename, $blob, $meta) {
            if "$!basedir/$path/artifacts/$filename".IO.e {
                my $message := "Attempt to replace artifact '$filename' in '$path', refusing";
                $log.warn($message);
                X::Shelved::ClientError.new(code => 403, :$message).throw;
            }
            # create path as required
            with "$!basedir/$path/".IO {
                .add('artifacts').mkdir;
                .add('meta').mkdir;
                .add('temp').mkdir;
            }

            with "$!basedir/$path/temp/$filename".IO {
                .spurt($blob);
                .rename("$!basedir/$path/artifacts/$filename");
            }

            with "$!basedir/$path/temp/$filename.meta".IO {
                .spurt($meta);
                .rename("$!basedir/$path/meta/$filename.meta");
            }

            $log.debug("Stored artifact $filename in $path");
        }

        method list-artifacts($path) {
            my @results = IO::Path.new("$!basedir/$path/artifacts").dir;
            @results.map(-> $i { $i.relative("$!basedir/$path/artifacts")})
        }

        method artifact-exists($path, $filename) {
            "$!basedir/$path/artifacts/$filename".IO.e
        }

        method get-meta($path, $name) {
            "$!basedir/$path/meta/$name.meta".IO.slurp
        }
    }
}

=begin pod

=head1 NAME

Shelved

=head1 DESCRIPTION

An artifact repository for the Raku Programming Language and friends

The goal is to build a artifact repository service that Raku modules, but
also other stuff, can be pushed to and pulled via the usual means (i.e.
pushed from CI or manual workflows, pulled via C<zef>). This would be
useful for an organisation doing Raku development, does not want all
their code publicly available, yet want to use a regular module-centric,
tarball/release-based development flow.

Essentially this is a "content storage" service as described in
L<S22|https://design.raku.org/S22.html#content_storage>.

=head1 FEATURES

=item Upload Raku modules
=item Fetch with zef
=item Authentication
=item Multiple configurable logical repos

=head1 Upcoming and ToDo

=item cucumis sextus tests
=item adress already in use error handling/reporting
=item UI to browse and manage
=item API to manage and automate
=item Local cache/proxy for other repositories, like CPAN. Could be just a cache, or a fetch-ahead full copy. Perhaps both, configurably.
=item Rarification/expiry of artifacts in configured repositories
=item Web hooks for automation
=item Verification and other plugins
=item Shared file store, multiple shelved instances. Or a database as a store.
=item More auth types
=item Full-blown monitoring, resilience etc
=item More metadata, like when uploaded and by whom. "on-behalf" in upload script so that a CI or automation job can say on whose command they uploaded

Also grep for the `XXX` fixmes in the code!

=head1 USAGE

Shelved comes as a web service that you can just start e.g. directly from
the checked-out source repository via C<RAKUDOLIB=lib bin/shelved>, or if
it is properly installed just via C<shelved>. It reads a config.yaml file,
a simple sample is included, and might look like this:

=begin code :lang<yaml>
    server:
        port: 8080
        base-url: "http://localhost:8080"
    store:
        basedir: store
    repositories:
        - name: p6repo
=end code

=item base-url

is where you want the service to be found externally.

=item port

is of course the port the service listens on, note that  it currently
only binds to the first localhost interface, let me know if that gives
you grief.

=item basedir

is a directory where shleve6 will store the artifacts.

=item repositories

is a list of logical artifact repositories in which you can store modules.

With the service running, you can use the supplied shelved-upload script to put
artifacts into shelved:

=begin code

bin/shelved-upload raku-foo-bar-0.1.tar.gz http://localhost:8080/repos/p6repo

=end code

This script is just a thin wrapper around C<curl>, you just need a multipart
form post really.

In order to fetch artifacts, you need to configure your C<zef> to recognise
the repository. In my case I have a C<~/.config/zef/config.json>, where in
the `Repository` section I added:

=begin code :lang<json>
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
=end code

After that, C<zef> happily pulls from shelved!

=head1 AUTHENTICATION / AUTHORIZATION

If you want to use the repository for private code, it may be a good idea to
enable some security on it. Shelved can use credentials in the request and map
them to a set of roles associated with that credential. Currently the only
credential type supported are 'opaque' tokens, these are just striings that are
not looked into (so not JWT or so). These come in a HTTP header like
`Authorization: Bearer supersecret`, where 'supersecret' is the credential. In
the future more credential types can be supported. To configure the mapping of
credentials to roles, extend the 'server' part of the configuration:

=begin code :lang<yaml>
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
=end code

In order to actually require any roles, you need to configure which roles allow
what operation, on the repository:

=begin code :lang<yaml>
repositories:
    - name: p6repo
      authorization:
        upload: [CI, DEV, ADMIN]
        download: [CI, DEV, ADMIN]
        delete: [ADMIN]
=end code

Note that the credential is associated with all the roles from the server
config, but any role in the repository section is sufficient for access
to be granted. For example the credential 'eng8ahquia2kungeitaequie' above
gives both the 'DEV' and the 'ADMIN' roles, any of which would be enough
to upload and download artifacts.

The C<shelved-upload> script supports setting these tokens through a
commandline argument or an environment variable.

In order to enable C<zef> to provide credentials during module fetching,
you need to install the C<Zef::Service::AuthenticatedDownload> plugin:

=begin code
    zef install Zef::Service::AuthenticatedDownload
=end code

And configure it. The C<zef> README explains where you can find the zef
config, where you can add the plugin and configure it, which is best
done before the other web fetchers to avoid them trying to download and
failing due to auth:

=begin code :lang<yaml>
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
=end code

This will make zef use the configured credential for the host in question. If
you do not want to put the credential into the config file, you can also leave
it out and supply it via the C<ZEF_AUTH_OPAQUE_TOKEN> environment variable.

=head1 AUTHORS

Robert Lemmen (2018-2020), Elizabeth Mattijsen <liz@raku.rocks> (2021-)

Originally developed as C<Shelve6> by Robert Lemmen, maintenance taken over
and renamed to C<Shelved> by Elizabeth Mattijsen.  The rename was deemed to
make sense in the context of the Raku Programming Language (which has no
special meaning for the number 6) and the fact that this module usually
runs as a daemon (hence the "d" at the end).

Source can be located at: https://github.com/lizmat/Shelved . Comments and
Pull Requests are welcome.

=head1 COPYRIGHT AND LICENSE

Copyright 2018-2020 Robert Lemmen, 2021 Elizabeth Mattijsen

This library is free software; you can redistribute it and/or modify it under the Artistic License 2.0.

=end pod

# vim: expandtab shiftwidth=4
