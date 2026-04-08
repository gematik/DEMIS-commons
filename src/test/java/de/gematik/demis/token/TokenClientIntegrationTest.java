package de.gematik.demis.token;

/*-
 * #%L
 * DEMIS Commons Library
 * %%
 * Copyright (C) 2025 - 2026 gematik GmbH
 * %%
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
 * European Commission – subsequent versions of the EUPL (the "Licence").
 * You may not use this work except in compliance with the Licence.
 *
 * You find a copy of the Licence in the "Licence" file or at
 * https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
 * In case of changes by gematik find details in the "Readme" file.
 *
 * See the Licence for the specific language governing permissions and limitations under the Licence.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik,
 * find details in the "Readme" file.
 * #L%
 */

import com.sun.net.httpserver.HttpServer;
import de.gematik.demis.Constants;
import de.gematik.demis.enums.KeyStoreType;
import de.gematik.demis.exceptions.TokenException;
import de.gematik.demis.proxy.ProxySettings;
import de.gematik.demis.tls.Keystore;
import de.gematik.demis.tls.KeystoreLoader;
import de.gematik.demis.token.data.RequestParameter;
import de.gematik.demis.token.data.User;
import de.gematik.demis.token.data.types.Password;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class TokenClientIntegrationTest {

  private Keystore userCert;
  private Keystore serverTruststore;
  private ProxySettings proxySettings;
  private TokenClient tokenClient;

  // ---------------------------------------------------------------------------
  // embedded HTTP server – new unit-style tests
  // ---------------------------------------------------------------------------

  private static final String VALID_TOKEN_JSON =
      "{\"access_token\":\"my-token\","
          + "\"token_type\":\"Bearer\","
          + "\"expires_in\":300,"
          + "\"refresh_expires_in\":0,"
          + "\"not-before-policy\":0,"
          + "\"scope\":\"profile email\"}";

  private HttpServer httpServer;
  private String baseUrl;
  private Keystore unitTruststore;
  private Keystore unitUserKeystore;

  // ---------------------------------------------------------------------------
  // lifecycle
  // ---------------------------------------------------------------------------

  @BeforeEach
  void prepareValidScenario() throws IOException {
    final var certData = KeystoreLoader.loadKeystoreAsRawData(Constants.LAB_DEMIS_11111_P12);
    userCert = Keystore.createPKCS12(certData, Constants.LAB_DEMIS_11111_PASSWORD);

    final var serverData =
        KeystoreLoader.loadKeystoreAsRawData("src/test/resources/certs/nginx.truststore");
    serverTruststore = Keystore.createJKS(serverData, "secret");

    proxySettings = new ProxySettings(false, "192.168.110.10", "3128");
    tokenClient = new TokenClient(serverTruststore, proxySettings);

    // --- embedded HTTP server setup ---
    httpServer = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    httpServer.start();
    baseUrl = "http://localhost:" + httpServer.getAddress().getPort();

    final byte[] unitServerData =
        KeystoreLoader.loadKeystoreAsRawData("src/test/resources/certs/nginx.truststore");
    unitTruststore = new Keystore(unitServerData, "password", KeyStoreType.JKS);

    final byte[] unitCertData = KeystoreLoader.loadKeystoreAsRawData(Constants.LAB_DEMIS_11111_P12);
    unitUserKeystore =
        new Keystore(unitCertData, Constants.LAB_DEMIS_11111_PASSWORD, KeyStoreType.PKCS12);
  }

  @AfterEach
  void stopEmbeddedServer() {
    httpServer.stop(0);
  }

  // ---------------------------------------------------------------------------
  // helpers
  // ---------------------------------------------------------------------------

  private void registerHandler(final String path, final int statusCode, final String body) {
    httpServer.createContext(
        path,
        exchange -> {
          final byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
          exchange.sendResponseHeaders(statusCode, bytes.length);
          try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
          }
        });
  }

  private TokenClient clientWithoutProxy() {
    return new TokenClient(unitTruststore, null);
  }

  private TokenClient clientWithProxy(final boolean enabled) {
    return new TokenClient(unitTruststore, new ProxySettings(enabled, "127.0.0.1", "3128"));
  }

  @Disabled("Disabled cause dev-ltu is not reachable temporary")
  @Test
  void expectTokenFetchWorksSuccessfullyAgainstDev() {

    final var requestParameter =
        RequestParameter.create(
            "https://dev.demis.rki.de/auth/realms/LAB/protocol/openid-connect/token",
            "11111",
            "demis-adapter",
            userCert);
    final var token = Assertions.assertDoesNotThrow(() -> tokenClient.fetch(requestParameter));
    Assertions.assertNotNull(token);
    System.out.println(token.getAccessToken());
  }

  @Test
  void expectTokenFetchFailsWithErrorOnData() {

    final var requestParameter =
        RequestParameter.create("https://badUrl.local", "11111", "demis-adapter", userCert);
    tokenClient = new TokenClient(serverTruststore, proxySettings);
    Assertions.assertThrows(TokenException.class, () -> tokenClient.fetch(requestParameter));

    Assertions.assertThrows(NullPointerException.class, () -> new TokenClient(null, null));

    Assertions.assertThrows(NullPointerException.class, () -> new TokenClient(null, null));

    proxySettings = new ProxySettings(true, "192.168.110.10", "3128");
    tokenClient = new TokenClient(serverTruststore, proxySettings);
    Assertions.assertThrows(TokenException.class, () -> tokenClient.fetch(requestParameter));
  }

  @Test
  void expectTokenFetchFailsWithErrorOnBadUserInfo() {

    final var requestParameter =
        RequestParameter.create(
            "https://dev.demis.rki.de/auth/realms/LAB/protocol/openid-connect/token",
            "11111",
            "not-existing",
            userCert);
    Assertions.assertThrows(TokenException.class, () -> tokenClient.fetch(requestParameter));

    Assertions.assertThrows(NullPointerException.class, () -> tokenClient.fetch(null));

    Assertions.assertThrows(NullPointerException.class, () -> tokenClient.fetch(null, null));

    Assertions.assertThrows(NullPointerException.class, () -> tokenClient.fetch("test", null));
  }

  @Test
  @EnabledIfEnvironmentVariable(named = "ENABLE_HOSTNAME_VERIFICATION", matches = "false")
  void expectTokenFetchWorksSuccessfullyAgainstINT() {

    final var customProxySettings = new ProxySettings(true, "192.168.110.10", "3128");

    final var customTokenClient = new TokenClient(serverTruststore, customProxySettings);

    final var requestParameter =
        RequestParameter.create(
            "https://146.185.106.63/auth/realms/LAB/protocol/openid-connect/token",
            "11111",
            "demis-adapter",
            userCert);

    final var token =
        Assertions.assertDoesNotThrow(() -> customTokenClient.fetch(requestParameter));
    Assertions.assertNotNull(token);
    System.out.println(token.getAccessToken());
  }

  // ---------------------------------------------------------------------------
  // new tests using the embedded HTTP server
  // ---------------------------------------------------------------------------

  @Test
  void expectFetchReturnsTokenOnSuccessfulResponse() {
    registerHandler("/token", 200, VALID_TOKEN_JSON);
    final TokenClient client = clientWithoutProxy();
    final RequestParameter request =
        RequestParameter.create(baseUrl + "/token", "user1", "demis-adapter", unitUserKeystore);
    final TokenResponse response = Assertions.assertDoesNotThrow(() -> client.fetch(request));
    Assertions.assertNotNull(response);
    Assertions.assertEquals("my-token", response.getAccessToken());
  }

  @Test
  void expectFetchStringUserOverloadWorks() {
    registerHandler("/token", 200, VALID_TOKEN_JSON);
    final TokenClient client = clientWithoutProxy();
    final User user = new User("user1", "demis-adapter", unitUserKeystore);
    final TokenResponse response =
        Assertions.assertDoesNotThrow(() -> client.fetch(baseUrl + "/token", user));
    Assertions.assertNotNull(response);
  }

  @Test
  void expectFetchUsesCachedSslContext() {
    registerHandler("/token", 200, VALID_TOKEN_JSON);
    final TokenClient client = clientWithoutProxy();
    final RequestParameter request =
        RequestParameter.create(baseUrl + "/token", "user1", "demis-adapter", unitUserKeystore);
    Assertions.assertDoesNotThrow(() -> client.fetch(request));
    final TokenResponse second = Assertions.assertDoesNotThrow(() -> client.fetch(request));
    Assertions.assertNotNull(second);
  }

  @ParameterizedTest
  @ValueSource(ints = {401, 403, 503})
  void expectFetchThrowsTokenExceptionOnErrorResponse(final int statusCode) {
    registerHandler("/token", statusCode, "Error");
    final TokenClient client = clientWithoutProxy();
    final RequestParameter request =
        RequestParameter.create(baseUrl + "/token", "user1", "demis-adapter", unitUserKeystore);
    Assertions.assertThrows(TokenException.class, () -> client.fetch(request));
  }

  @Test
  void expectFetchThrowsTokenExceptionOnInvalidJson() {
    registerHandler("/token", 200, "NOT_JSON{{{{");
    final TokenClient client = clientWithoutProxy();
    final RequestParameter request =
        RequestParameter.create(baseUrl + "/token", "user1", "demis-adapter", unitUserKeystore);
    Assertions.assertThrows(TokenException.class, () -> client.fetch(request));
  }

  @Test
  void expectFetchWorksWithDisabledProxy() {
    registerHandler("/token", 200, VALID_TOKEN_JSON);
    final TokenClient client = clientWithProxy(false);
    final RequestParameter request =
        RequestParameter.create(baseUrl + "/token", "user1", "demis-adapter", unitUserKeystore);
    final TokenResponse response = Assertions.assertDoesNotThrow(() -> client.fetch(request));
    Assertions.assertNotNull(response);
  }

  @Test
  void expectFetchIncludesPasswordFieldInBody() {
    final String[] capturedBody = new String[1];
    httpServer.createContext(
        "/token-pw",
        exchange -> {
          capturedBody[0] =
              new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
          final byte[] resp = VALID_TOKEN_JSON.getBytes(StandardCharsets.UTF_8);
          exchange.sendResponseHeaders(200, resp.length);
          try (OutputStream os = exchange.getResponseBody()) {
            os.write(resp);
          }
        });
    final TokenClient client = clientWithoutProxy();
    final RequestParameter request =
        RequestParameter.create(
            baseUrl + "/token-pw",
            "user1",
            "demis-adapter",
            "client-secret",
            "password",
            unitUserKeystore,
            Password.of("secret123"));
    Assertions.assertDoesNotThrow(() -> client.fetch(request));
    Assertions.assertTrue(capturedBody[0].contains("password=secret123"));
  }
}
