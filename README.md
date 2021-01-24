# otsshd

One-Time SSH Daemon, written in Go.

Inspired by the proposal in https://github.com/grncdr/otssh.

## Install

```
go get github.com/jamespwilliams/otsshd
```

## Usage

```
usage: otsshd [-addr=:2022] [-log=<filename>] [-announce=<cmd>] -authorized-keys=<filename>

Starts an SSH server with a new host key that will run for exactly one session.
The generated host key will be printed to stdout.
```


## Options

| Flag              | Type   | Description                                                                                                                                                                                                                      | Default   |
|-------------------|--------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------|
| `-addr`           | string | Address to listen for connections on                                                                                                                                                                                             | :2022     |
| `-announce`       | string | Command which will be invoked with the generated host key as its first argument                                                                                                                                                  |           |
| `authorized-keys` | string | Path to file containing the public keys of users who will be allowed access to the SSH server. Should be in the same format as the OpenSSH `authorized_keys` file. The file will be read from stdin if this flag isn't provided. |           |
| `copy-env`        | bool   | Copy environment variables to the child session                                                                                                                                                                                  | true      |
| `log`             | string | Path to log session input and output to                                                                                                                                                                                          | otssh.log |
| `timeout`         | int    | Time to wait for a connection before exiting, in seconds                                                                                                                                                                         | 600       |
|                   |        |                                         
