"""
UDP endpoit for the Rendezvous server.

Listens for probe packets (16-byte nonces) and reports observed source
addresses back to the TCP handlers that waiting on the those nonces.

The glue: each TCP session registers a Future keyed by the nonce it gave
to the peer. When a UDP probe with that nonce arrives, we set the future's
result to the probe's source address.
"""

import asyncio
import logging
from typing import Optional

log = logging.getLogger("rendezvous.udp")

NONCE_SIZE = 16 # 128 bits


class UDPObserver(asyncio.DatagramProtocol):
    """
    asyncio DatagramProtocol that dispatches probes to waiting futures.

    A single instance handles all peers; per-session coordination happens
    through the `pending` dict keyed by nonce.
    """
