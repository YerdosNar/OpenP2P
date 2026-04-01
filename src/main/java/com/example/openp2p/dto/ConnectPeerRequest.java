package com.example.openp2p.dto;

/**
 * ConnectPeerRequest
 */
public record ConnectPeerRequest(
        String hostId,
        String password,
        int hostPort
) {}
