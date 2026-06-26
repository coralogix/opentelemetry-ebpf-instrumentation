// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

import com.aerospike.client.AerospikeClient;
import com.aerospike.client.Bin;
import com.aerospike.client.Host;
import com.aerospike.client.Key;
import com.aerospike.client.policy.ClientPolicy;
import com.sun.net.httpserver.HttpServer;

import java.io.OutputStream;
import java.net.InetSocketAddress;

/**
 * Minimal HTTP server that triggers a deterministic sequence of Aerospike record
 * operations (PUT, GET, DELETE, SCAN) on every request, so OBI can observe them
 * passively over the wire. Uses the com.aerospike:aerospike-client-jdk21 client.
 */
public class Aerospike {
    private static final String NAMESPACE = "test";
    private static final String SET = "demo";

    public static void main(String[] args) throws Exception {
        ClientPolicy policy = new ClientPolicy();
        policy.timeout = 10_000;

        AerospikeClient client = null;
        // The server may still be starting up; retry the initial connection.
        for (int i = 0; i < 30 && client == null; i++) {
            try {
                client = new AerospikeClient(policy, new Host("aerospike", 3000));
            } catch (Exception e) {
                System.out.println("waiting for aerospike: " + e.getMessage());
                Thread.sleep(1000);
            }
        }
        if (client == null) {
            System.err.println("could not connect to aerospike");
            return;
        }

        final AerospikeClient as = client;
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/", exchange -> {
            try {
                Key key = new Key(NAMESPACE, SET, "obi");
                as.put(null, key, new Bin("product", "rocks")); // PUT
                as.get(null, key);                               // GET
                as.delete(null, key);                            // DELETE
                as.scanAll(null, NAMESPACE, SET, (k, rec) -> {
                }); // SCAN
            } catch (Exception e) {
                System.out.println("op failed: " + e.getMessage());
            }
            byte[] resp = "ok".getBytes();
            exchange.sendResponseHeaders(200, resp.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(resp);
            }
        });
        server.setExecutor(null);
        System.out.println("starting HTTP server on :8080");
        server.start();
    }
}
