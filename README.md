# chkimg

A command line tool to check [minidump
files](https://docs.microsoft.com/en-us/windows/desktop/Debug/minidump-files)
for memory corruption, fashioned after
[windbg's `!chkimg` command](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/-chkimg).

## Installation instructions

First, ensure you have [Rust installed](https://rustup.rs/).  Then, from some
directory you can write to:

```
$ git clone https://github.com/heycam/chkimg
...
$ cd chkimg
$ cargo install
```

## Usage

```
$ chkimg --help
USAGE:
    chkimg [OPTIONS] <MINIDUMP>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --skip-module <skip-module>...        name of a module to skip checking, e.g. "ntdll.dll"
        --symbol-cache <symbol-cache>         directory to cache files downloaded from symbol servers
        --symbol-server <symbol-server>...    URL of symbol server to download binaries from

ARGS:
    <MINIDUMP>    specifies the input minidump file
```

For example:

```
$ chkimg --symbol-cache=/tmp/symcache \
> --symbol-server=https://msdl.microsoft.com/download/symbols \
> --symbol-server=https://symbols.mozilla.org/ \
> /tmp/some-minidump-file.dmp
info: looking for xul.dll at https://msdl.microsoft.com/download/symbols...
info: looking for xul.dll at https://symbols.mozilla.org/...
info: fetching xul.dl_ from https://symbols.mozilla.org/...
info: looking for ntdll.dll at https://msdl.microsoft.com/download/symbols...
info: fetching ntdll.dll from https://msdl.microsoft.com/download/symbols...
crashing IP: 0x64a4175f
mismatch: 0x64a4175a .. 0x64a4175a (1 byte) in xul.dll
  [ a9 ] should be [ 89 ]
mismatch: 0x64a418e2 .. 0x64a418e3 (2 bytes) in xul.dll
  [ a7 64 ] should be [ 49 10 ]
```

## Issues

* Probably doesn’t support minidumps from any platform other than Windows.
* Doesn’t support some symbol server features, like <code>file.ptr</code> files.
