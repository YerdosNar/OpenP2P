
```ascii
p2p-chat/
├── rendezvous/
│   ├── __init__.py
│   ├── server.py          # The Rendezvous server (listens for peers)
│   └── room.py            # Room state: ID, PW, host info, 3-min timer
├── peer/
│   ├── __init__.py
│   ├── client.py          # Peer-side logic: connects to Rendezvous, then to other peer
│   ├── chat.py            # Chat UI and message handling
│   └── transfer.py        # File send/receive logic
├── common/
│   ├── __init__.py
│   ├── crypto.py          # Key generation, ECDH, derivation — shared by both sides
│   ├── protocol.py        # Message framing and message types (wire format)
│   └── socket_utils.py    # SO_REUSEPORT / SO_REUSEADDR helpers, cross-platform
├── certs/                 # Self-signed TLS certs for QUIC (generated once)
├── requirements.txt
├── run_rendezvous.py      # Entry point: python run_rendezvous.py
├── run_peer.py            # Entry point: python run_peer.py
└── README.md
```
