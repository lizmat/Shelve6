unit module Shelve6::Config:ver<0.3.0>:auth<zef:lizmat>;

use YAMLish:ver<0.0.6>;
use JSON::Fast:ver<0.0.16>;

sub load-config($filename) is export {
    try {
        die "no such file" if not $filename.IO.e;

        given ($filename) {
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
    if $! {
        die "Failed to read config file '$filename': {$!.Str}";
    }
}
