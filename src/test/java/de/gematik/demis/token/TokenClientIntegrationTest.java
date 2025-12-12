package de.gematik.demis.token;

/*-
 * #%L
 * DEMIS Commons Library
 * %%
 * Copyright (C) 2025 gematik GmbH
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

import de.gematik.demis.Constants;
import de.gematik.demis.exceptions.TokenException;
import de.gematik.demis.proxy.ProxySettings;
import de.gematik.demis.tls.Keystore;
import de.gematik.demis.tls.KeystoreLoader;
import de.gematik.demis.token.data.RequestParameter;
import java.io.IOException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

class TokenClientIntegrationTest {
  private Keystore userCert;

  private Keystore serverTruststore;

  private ProxySettings proxySettings;
  private TokenClient tokenClient;

  @BeforeEach
  void prepareValidScenario() throws IOException {
    final var certData = KeystoreLoader.loadKeystoreAsRawData(Constants.LAB_DEMIS_11111_P12);
    userCert = Keystore.createPKCS12(certData, Constants.LAB_DEMIS_11111_PASSWORD);

    final var serverData =
        KeystoreLoader.loadKeystoreAsRawData("src/test/resources/certs/nginx.truststore");
    serverTruststore = Keystore.createJKS(serverData, "secret");

    proxySettings = new ProxySettings(false, "192.168.110.10", "3128");

    tokenClient = new TokenClient(serverTruststore, proxySettings);
  }

  @Disabled // Disabled cause dev-ltu is not reachable temporary
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
}
