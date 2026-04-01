
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Peer {

        // IMPORTANT: Replace with your actual VPS IP
        private static final String SERVER_URL = "http://<YOUR-VPS-IP>:8888/api/rendezvous";
        private static final HttpClient httpClient = HttpClient.newHttpClient();

        public static void main(String[] args) throws Exception {
                Scanner scanner = new Scanner(System.in);

                System.out.println("=== P2P Terminal Messenger ===");
                System.out.println("1. Start as Host");
                System.out.println("2. Connect as Peer");
                System.out.print("Choose (1/2): ");
                int choice = scanner.nextInt();
                scanner.nextLine(); // consume newline

                if (choice == 1) {
                        runAsHost(scanner);
                } else if (choice == 2) {
                        runAsPeer(scanner);
                } else {
                        System.out.println("Invalid choice.");
                }
        }

        private static void runAsHost(Scanner scanner) throws Exception {
                System.out.print("Enter your Host ID (e.g., Host1): ");
                String hostId = scanner.nextLine();
                System.out.print("Create a session password: ");
                String password = scanner.nextLine();
                System.out.print("Enter local port for P2P (e.g., 5050): ");
                int localPort = scanner.nextInt();

                // 1. Register with the server
                String jsonPayload = String.format("{\"hostId\":\"%s\", \"password\":\"%s\", \"port\":%d}", hostId, password, localPort);

                HttpRequest registerReq = HttpRequest.newBuilder()
                .uri(URI.create(SERVER_URL + "/host"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                .build();

                HttpResponse<String> registerRes = httpClient.send(registerReq, HttpResponse.BodyHandlers.ofString());

                if (registerRes.statusCode() != 200) {
                        System.out.println("Failed to register: " + registerRes.body());
                        return;
                }
                System.out.println("Registered successfully! Waiting for peer to connect...");

                // 2. Poll for Peer 2's info
                HttpRequest statusReq = HttpRequest.newBuilder()
                .uri(URI.create(SERVER_URL + "/host/" + hostId + "/status"))
                .GET()
                .build();

                while (true) {
                        HttpResponse<String> statusRes = httpClient.send(statusReq, HttpResponse.BodyHandlers.ofString());

                        if (statusRes.statusCode() == 200) {
                                // Peer joined! Parse their coordinates using basic string extraction
                                String responseBody = statusRes.body();
                                String peerIp = extractJsonValue(responseBody, "ip");
                                int peerPort = Integer.parseInt(extractJsonValue(responseBody, "port"));

                                System.out.println("=== PEER FOUND ===");
                                System.out.printf("Target Coordinates -> IP: %s | Port: %d%n", peerIp, peerPort);
                                System.out.println("Ready to initiate TCP Hole Punching...");
                                break; // Exit the polling loop
                        } else if (statusRes.statusCode() == 202) {
                                // Still waiting
                                Thread.sleep(2000);
                        } else {
                                System.out.println("Error or session expired: " + statusRes.body());
                                break;
                        }
                }
        }

        private static void runAsPeer(Scanner scanner) throws Exception {
                System.out.print("Enter target Host ID (e.g., Host1): ");
                String hostId = scanner.nextLine();
                System.out.print("Enter session password: ");
                String password = scanner.nextLine();
                System.out.print("Enter local port for P2P (e.g., 6060): ");
                int localPort = scanner.nextInt();

                // Connect and retrieve Host info
                String jsonPayload = String.format("{\"hostId\":\"%s\", \"password\":\"%s\", \"port\":%d}", hostId, password, localPort);

                HttpRequest connectReq = HttpRequest.newBuilder()
                .uri(URI.create(SERVER_URL + "/peer"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                .build();

                HttpResponse<String> connectRes = httpClient.send(connectReq, HttpResponse.BodyHandlers.ofString());

                if (connectRes.statusCode() == 200) {
                        String responseBody = connectRes.body();
                        String hostIp = extractJsonValue(responseBody, "ip");
                        int hostPort = Integer.parseInt(extractJsonValue(responseBody, "port"));

                        System.out.println("=== HOST FOUND ===");
                        System.out.printf("Target Coordinates -> IP: %s | Port: %d%n", hostIp, hostPort);
                        System.out.println("Ready to initiate TCP Hole Punching...");
                } else {
                        System.out.println("Failed to connect: " + connectRes.body());
                }
        }

        // A lightweight helper to extract values from a simple JSON string without a library
        private static String extractJsonValue(String json, String key) {
                String patternString = "\"" + key + "\"\\s*:\\s*\"?([^\"},]+)\"?";
                Pattern pattern = Pattern.compile(patternString);
                Matcher matcher = pattern.matcher(json);
                if (matcher.find()) {
                        return matcher.group(1).trim();
                }
                return "0";
        }
}
