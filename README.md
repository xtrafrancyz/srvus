# srvus

Expose your local server to the internet with ease.

This is a fork of [pcarrier/srv.us](https://github.com/pcarrier/srv.us) with the support for tcp tunneling and removed web utilities.

## Usage

Tunnel Minecraft server (any TCP)

```bash
$ ssh -p 2222 tcp@your.custom.domain -R 0:127.0.0.1:25565

Docs: https://your.custom.domain/docs

TCP: your.custom.domain:52134
```

Tunnel HTTP server

```bash
$ ssh -p 2222 your.custom.domain -R 0:127.0.0.1:8080

Docs: https://your.custom.domain/docs

0: https://xxxxxxxxxxxxxxxxxxxx.your.custom.domain
```
