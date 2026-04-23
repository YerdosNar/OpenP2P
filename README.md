# OpenP2P:

1. Peer1 connects to the Rendezvous by sending his public key. Rendezvous responds by sending Peer1 Rendezvous's public key.
2. After the first exchange, they establish E2EE connection.
3. Rendezvous sends "Are you [H]ost or [J]oin? [h/j]: " message.\
(For this example)
4. Peer1 sends "h" message, meaning Peer1 will host a room.
5. Rendezvous asks "Enter HostRoom ID: ".
6. Peer1 sends an ID.
7. Rendezvous checks if the ID is unique. If there is a room with that ID, then Rendezvous sends error to Peer1.
8. Rendezvous asks "Enter HostRoom PW: "
9. Peer1 sends PW for the room.
10. Rendezvous creates a room with those credentials, and notifies Peer1. Starts 3 minute timer.\
    10.1. If no one joins within 3 minutes, then the room gets deleted.

11. Peer2 connects to the Rendezvous by sending his public key. Rendezvous responds by sending Peer2 Rendezvous's public key.
12. After the first exchange, they establish E2EE connection.
13. Rendezvous sends "Are you [H]ost or [J]oin? [h/j]: " message.\
(For this example)
14. Peer2 sends "j" message, meaning Peer1 will join a room.
15. Rendezvous asks "Enter HostRoom ID: ".
16. Peer2 sends an ID.
17. Rendezvous asks "Enter HostRoom PW: "
18. Peer2 sends PW for the room.
19. Rendezvous checks, if credentials (ID or password) don't match. The Peer2 is kicked.
20. If credentials are correct. Then Rendezvous sends Peer1 Peer2's info (IP:Port + Public Key), and sends Peer2 Peer1's info (IP:Port + Public Key). And disconnect from both of them. No server in the middle.
21. Both peers initiate UDP hole punch to each other.
22. Since both have the other side's public key, they establish E2EE connection from the first message.
23. They start chatting + file transfer.
