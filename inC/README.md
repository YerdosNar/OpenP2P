/*
 * OpenP2P
 *
 * take one peer1's IP:Port
 * peer1 becomes the host
 * peer1 sets a password and ID
 * ID -> to find if the host exist
 * Password -> to join the hosted room
 *
 * set a timer for 3 minutes
 * if (host_expired()) {
 *      delete_room();
 * }
 * else {
 *      wait_for_peer2();
 * }
 *
 * take peer2's IP:Port
 * ask for ID
 * if (input_id == host_id) {
 *      ask for password
 *      if (input_pw == host_pw) {
 *              sendIPs();
 *      }
 * }
 *
 * supported flag:
 *      -p, --port [num]        port to listen for peers
 *      -l, --log [filename]   to log connections (default filename: "con.log")
 *
 *
 * FURTHER IMPROVEMENTS:
 *      Add threads, there will be threads for each
 */


