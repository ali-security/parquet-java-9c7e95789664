/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.parquet.format;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import org.apache.thrift.transport.TSSLTransportFactory;
import org.apache.thrift.transport.TSSLTransportFactory.TSSLTransportParameters;
import org.apache.thrift.transport.TSocket;
import org.apache.thrift.transport.TTransportException;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 * The libthrift embedded into this module must be a build whose TLS client sockets check that the server certificate
 * was issued for the host they connect to (CVE-2026-43869). Otherwise any certificate the client trusts, issued for
 * some other host, lets its holder impersonate the server.
 */
public class TestThriftSslHostVerification {

  private static final String PASSWORD = "parquet";
  private static final String HOST = "127.0.0.1";
  private static final int TIMEOUT_MILLIS = 30000;
  private static final byte[] MESSAGE = {1};

  @Rule
  public TemporaryFolder tmpFolder = new TemporaryFolder();

  @Test
  public void testClientRejectsTrustedCertificateIssuedForAnotherHost() throws Exception {
    File keyStore = createKeyStore("attacker", "dns:attacker.example");

    // The certificate is trusted: a client socket without host verification, as before the fix, accepts it
    try (TlsServer server = new TlsServer(keyStore)) {
      SSLContext context = clientContext(keyStore);
      try (SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket(HOST, server.getPort())) {
        assertNull(socket.getSSLParameters().getEndpointIdentificationAlgorithm());
        socket.startHandshake();
      }
    }

    try (TlsServer server = new TlsServer(keyStore)) {
      TSocket client = connect(server, keyStore);
      try {
        SSLSocket socket = (SSLSocket) client.getSocket();
        assertEquals("HTTPS", socket.getSSLParameters().getEndpointIdentificationAlgorithm());
        client.write(MESSAGE);
        client.flush();
        fail("The TLS handshake must fail for a certificate that was not issued for " + HOST);
      } catch (TTransportException e) {
        assertTrue("Expected a TLS handshake failure but got " + e, isHandshakeFailure(e));
      } finally {
        client.close();
      }
    }
  }

  @Test
  public void testClientAcceptsCertificateIssuedForTheHost() throws Exception {
    File keyStore = createKeyStore("server", "ip:" + HOST);

    try (TlsServer server = new TlsServer(keyStore)) {
      TSocket client = connect(server, keyStore);
      try {
        client.write(MESSAGE);
        client.flush();
        assertTrue(((SSLSocket) client.getSocket()).getSession().isValid());
      } finally {
        client.close();
      }
    }
  }

  private static TSocket connect(TlsServer server, File trustStore) throws TTransportException {
    TSSLTransportParameters params = new TSSLTransportParameters();
    params.setTrustStore(trustStore.getPath(), PASSWORD, TrustManagerFactory.getDefaultAlgorithm(), "PKCS12");
    return TSSLTransportFactory.getClientSocket(HOST, server.getPort(), TIMEOUT_MILLIS, params);
  }

  private static SSLContext clientContext(File trustStore) throws Exception {
    TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    factory.init(loadKeyStore(trustStore));
    SSLContext context = SSLContext.getInstance("TLS");
    context.init(null, factory.getTrustManagers(), null);
    return context;
  }

  private static boolean isHandshakeFailure(Throwable e) {
    for (Throwable cause = e; cause != null; cause = cause.getCause()) {
      if (cause instanceof SSLHandshakeException) {
        return true;
      }
    }
    return false;
  }

  private File createKeyStore(String alias, String subjectAlternativeName) throws Exception {
    File keyStore = new File(tmpFolder.getRoot(), alias + ".p12");
    List<String> command = new ArrayList<>();
    command.add(Paths.get(System.getProperty("java.home"), "bin", "keytool").toString());
    command.addAll(Arrays.asList("-genkeypair", "-alias", alias, "-dname", "CN=" + alias));
    command.addAll(Arrays.asList("-ext", "SAN=" + subjectAlternativeName, "-keyalg", "RSA", "-keysize", "2048"));
    command.addAll(Arrays.asList("-validity", "1", "-storetype", "PKCS12", "-keystore", keyStore.getPath()));
    command.addAll(Arrays.asList("-storepass", PASSWORD, "-keypass", PASSWORD));
    Process process = new ProcessBuilder(command).inheritIO().start();
    assertEquals("keytool failed, see the test output", 0, process.waitFor());
    return keyStore;
  }

  private static KeyStore loadKeyStore(File file) throws Exception {
    KeyStore keyStore = KeyStore.getInstance("PKCS12");
    try (InputStream in = new FileInputStream(file)) {
      keyStore.load(in, PASSWORD.toCharArray());
    }
    return keyStore;
  }

  /**
   * A TLS server presenting the certificate of the given key store to every client.
   */
  private static final class TlsServer implements AutoCloseable {

    private final SSLServerSocket serverSocket;
    private final Thread acceptor;

    TlsServer(File keyStore) throws Exception {
      KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
      keyManagers.init(loadKeyStore(keyStore), PASSWORD.toCharArray());
      SSLContext context = SSLContext.getInstance("TLS");
      context.init(keyManagers.getKeyManagers(), null, null);
      SSLServerSocketFactory factory = context.getServerSocketFactory();
      serverSocket = (SSLServerSocket) factory.createServerSocket(0, 1, InetAddress.getByName(HOST));
      acceptor = new Thread(this::serve, "tls-server");
      acceptor.setDaemon(true);
      acceptor.start();
    }

    int getPort() {
      return serverSocket.getLocalPort();
    }

    private void serve() {
      while (!serverSocket.isClosed()) {
        try (SSLSocket socket = (SSLSocket) serverSocket.accept()) {
          socket.setSoTimeout(TIMEOUT_MILLIS);
          socket.startHandshake();
          socket.getInputStream().read();
        } catch (IOException e) {
          // a client that rejects the certificate aborts the handshake
        }
      }
    }

    @Override
    public void close() throws Exception {
      serverSocket.close();
      acceptor.join(TIMEOUT_MILLIS);
    }
  }
}
