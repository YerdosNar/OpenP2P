# OpenP2P

Simple P2P messenger and file transfer terminal app.

## Building:
```bash
git clone https://github.com/YerdosNar/OpenP2P.git
cd OpenP2P
make # it will compile both (peer, rendezvous)
```
>`make clean` to clean up

## Peer:
```ascii
Usage: ./peer [options]

Options:
  -s, --server-port <port>    Rendezvous server port  (default=8888)
  -i, --ip <ip>               Rendezvous server IP    (default=127.0.0.1)
  -l, --local-port <port>     Local port for P2P      (default=50000)
  -d, --domain-name <name>    Rendezvous server domain
  -h, --help                  Show this help message

Example:
  ./peer -d example.com -s 8888
```
## Rendezvous:
```ascii
Usage: ./rendezvous [options]

Options:
  -p, --port <port>        Listening port          (default=8888)
  -l, --log <file>         Log filename            (default=con.log)
  -m, --max-rooms <n>      Max rooms in queue      (default=5000)
  -h, --help               Show this help message

Example:
  ./rendezvous -p 2222 -l server.log
```
