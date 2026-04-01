package com.example.openp2p.service;

import org.springframework.stereotype.Service;

import com.example.openp2p.dto.ConnectionInfoResponse;
import com.example.openp2p.model.SessionRoom;
import com.example.openp2p.repository.SessionRoomRepository;

/**
 * RendezvousService
 */
@Service
public class RendezvousService {

        private final SessionRoomRepository repository;

        public RendezvousService(SessionRoomRepository repository) {
                this.repository = repository;
        }

        public void registerHost(
                String hostId,
                String password,
                String hostIp,
                int hostPort
        ) {
                // Create the room. The @RedisHash annotation ensures
                // this will automatically vanish in 3 minutes (180 sec)
                SessionRoom room = new SessionRoom(hostId, password, hostIp, hostPort);
                repository.save(room);
        }

        public ConnectionInfoResponse connectPeer(String hostId, String password, String peerIp, int peerPort) {
                // find the room (ID)
                SessionRoom room = repository.findById(hostId)
                        .orElseThrow(() -> new IllegalArgumentException("Host not found or expired."));

                // verify password
                if (!room.getPassword().equals(password)) {
                        throw new IllegalArgumentException("Invalid password");
                }

                // save peer2 info, so the host can get it
                room.setPeerIp(peerIp);
                room.setPeerPort(peerPort);
                repository.save(room);

                // return host's network coordinates to peer2
                return new ConnectionInfoResponse(room.getHostIp(), room.getHostPort());
        }

        public ConnectionInfoResponse checkHostStatus(String hostId) {
                // find the room
                SessionRoom room = repository.findById(hostId)
                        .orElseThrow(() -> new IllegalArgumentException("Room expired or not found."));

                // check peer2 info
                if (room.getPeerIp() != null && room.getPeerPort() != 0) {
                        // extract peer2 info
                        ConnectionInfoResponse peerInfo = new ConnectionInfoResponse(room.getPeerIp(), room.getPeerPort());
                        // clean up
                        // Since connnection is established, we can delete room
                        repository.deleteById(hostId);

                        return peerInfo;
                }

                // null if peer2 hasn't connected
                return null;
        }
}
