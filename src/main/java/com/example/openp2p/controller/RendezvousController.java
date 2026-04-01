package com.example.openp2p.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.openp2p.dto.ConnectPeerRequest;
import com.example.openp2p.dto.ConnectionInfoResponse;
import com.example.openp2p.dto.RegisterHostRequest;
import com.example.openp2p.service.RendezvousService;

import jakarta.servlet.http.HttpServletRequest;

/**
 * RendezvousController
 */
@RestController
@RequestMapping("/api/rendezvous")
public class RendezvousController {

        private final RendezvousService service;

        public RendezvousController(RendezvousService service) {
                this.service = service;
        }

        @PostMapping("/host")
        public ResponseEntity<String> registerHost(
                @RequestBody RegisterHostRequest request,
                HttpServletRequest httpRequest
        ) {
                String hostIp = httpRequest.getRemoteAddr();
                service.registerHost(request.hostId(), request.password(), hostIp, request.hostPort());

                return ResponseEntity.ok("Host registered successfully. Room expires in 3 mins.");
        }

        @PostMapping("/peer")
        public ResponseEntity<?> connectPeer(
                @RequestBody ConnectPeerRequest request,
                HttpServletRequest httpRequest
        ) {
                try {
                        // get Peer2 IP
                        String peerIp = httpRequest.getRemoteAddr();

                        ConnectionInfoResponse hostInfo = service.connectPeer(
                                request.hostId(),
                                request.password(),
                                peerIp,
                                request.hostPort()
                        );

                        return ResponseEntity.ok(hostInfo);
                }
                catch (IllegalArgumentException e) {
                        // return 400 bad req if the host isn't found or pw is wrong
                        return ResponseEntity.badRequest().body(e.getMessage());
                }
        }
}
