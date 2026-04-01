package com.example.openp2p.model;

import org.springframework.data.redis.core.RedisHash;
import jakarta.persistence.Id;

/**
 * SessionRoom
 */
@RedisHash(value = "SessionRoom", timeToLive = 180)
public class SessionRoom {

        @Id
        private String hostId;
        private String password;

        private String hostIp;
        private int hostPort;

        private String peerIp;
        private int peerPort;

        public SessionRoom(String hostId, String password, String hostIp, int hostPort) {
                this.hostId = hostId;
                this.password = password;
                this.hostIp = hostIp;
                this.hostPort = hostPort;
        }

        public String getHostId() {return hostId;}
        public String getPassword() {return password;}
        public String getHostIp() {return hostIp;}
        public int getHostPort() {return hostPort;}

        public String getPeerIp() {return peerIp;}
        public int getPeerPort() {return peerPort;}

        public void setHostId(String hostId) {this.hostId = hostId;}
        public void setPassword(String password) {this.password = password;}
        public void setHostIp(String hostIp) {this.hostIp = hostIp;}
        public void setHostPort(int hostPort) {this.hostPort = hostPort;}

        public void setPeerIp(String peerIp) {this.peerIp = peerIp;}
        public void setPeerPort(int peerPort) {this.peerPort = peerPort;}
}
