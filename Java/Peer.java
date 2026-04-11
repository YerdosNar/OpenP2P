import java.util.Scanner;

/**
 * Peer
 */
public class Peer {

        public static void main(String[] args) {
                boolean direct = false;
                int portNum;
                Scanner sc = new Scanner(System.in);

                if (args[1].equals("--direct")) {
                        direct = true;
                }

                System.out.println("Input peer number: ");
                portNum = sc.nextInt();

                if (!direct) {
                        connectToRendezvous();
                        doKeyExchange();
                        createRoom();
                }
                getPeerInfo();
                startChat();

                sc.close();
        }
}
