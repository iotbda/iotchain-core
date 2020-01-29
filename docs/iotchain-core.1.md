% iotchain-core(1)
% IOTChain Development Foundation
%

# NAME

iotchain-core - Core daemon for IOTChain payment network

# SYNOPSYS

iotchain-core [OPTIONS]

# DESCRIPTION

IOTChain is a decentralized, federated peer-to-peer network that allows
people to send payments in any asset anywhere in the world
instantaneously, and with minimal fee. `IOTChain-core` is the core
component of this network. `IOTChain-core` is a C++ implementation of
the IOTChain Consensus Protocol configured to construct a chain of
ledgers that are guaranteed to be in agreement across all the
participating nodes at all times.

## Configuration file

In most modes of operation, iotchain-core requires a configuration
file.  By default, it looks for a file called `iotchain-core.cfg` in
the current working directory, but this default can be changed by the
`--conf` command-line option.  The configuration file is in TOML
syntax.  The full set of supported directives can be found in
`%prefix%/share/doc/iotchain-core_example.cfg`.

%commands%

# EXAMPLES

See `%prefix%/share/doc/*.cfg` for some example iotchain-core
configuration files

# FILES

iotchain-core.cfg
:   Configuration file (in current working directory by default)

# SEE ALSO

<https://iotbdalliance.com/developers/iotchain-core/software/admin.html>
:   iotchain-core administration guide

<https://iotbdalliance.com>
:   Home page of IOTChain development foundation

# BUGS

Please report bugs using the github issue tracker:\
<https://github.com/iotbda/iotchain-core/issues>
