# jaws

Personal tools for day to day AWS tasks.
Not likely to be of use to anybody but the author.

## Installation

Build from scratch:

    git clone https://github.com/dtenny/jaws.git
    cd jaws
    lein install

Or reference the appropriate version from clojars.

The lastest version is [jaws 0.1.1].

## Usage

jaws.native is a library for embedding in other applications.
So add (:use jaws.native) to your (ns) directive, or however you like it.

## Version 0.1.0 -> 0.1.1 compatibility notes.

Version 0.1.0 implicitly sucked up credential files matching
~/<token>.aws.cred from the user's home directory.  That is no longer done
after 0.1.0.  You have to explicitly call 'add-cred-file',
'add-cred-files', or 'def-cred' to get credentials into memory.

The 0.1.0 semantics of 'defcred' is now embodied 'use-cred'.
You'll need to change all callers of defcred to be use-cred.
This would ordinarily necessitate a minor version update at the least,
but since the audience is limited to the author at this time that hasn't
been done.

## License

Copyright © 2014 Jeffrey D. Tenny

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
