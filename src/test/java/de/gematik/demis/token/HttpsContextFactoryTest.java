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
import de.gematik.demis.DemisConstants;
import de.gematik.demis.enums.KeyStoreType;
import de.gematik.demis.exceptions.KeystoreException;
import de.gematik.demis.tls.HttpsContextFactory;
import de.gematik.demis.tls.Keystore;
import de.gematik.demis.tls.KeystoreLoader;
import java.io.IOException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ExtendWith(SystemStubsExtension.class)
class HttpsContextFactoryTest {

  @SystemStub private EnvironmentVariables environment;

  @Test
  void expectCreateSslContextWorksSuccessfully() throws IOException {
    final var certData = KeystoreLoader.loadKeystoreAsRawData(Constants.LAB_DEMIS_11111_P12);
    final Keystore userKeystore =
        new Keystore(certData, Constants.LAB_DEMIS_11111_PASSWORD, KeyStoreType.PKCS12);

    final var serverData =
        KeystoreLoader.loadKeystoreAsRawData("src/test/resources/certs/nginx.truststore");
    final Keystore serverTruststore = new Keystore(serverData, "password", KeyStoreType.JKS);

    final var context =
        Assertions.assertDoesNotThrow(
            () -> HttpsContextFactory.createSslContext(userKeystore, serverTruststore));
    Assertions.assertNotNull(context);
  }

  @Test
  void createSslParameters() {
    final var params =
        Assertions.assertDoesNotThrow(() -> HttpsContextFactory.createSslParameters(true));
    Assertions.assertNotNull(params);
  }

  @Test
  void expectErrorOnInvalidParams() throws IOException {
    final var certData = KeystoreLoader.loadKeystoreAsRawData(Constants.LAB_DEMIS_11111_P12);
    final Keystore badKeyStore = new Keystore(certData, "ACBI40OS1", KeyStoreType.JKS);

    Assertions.assertThrows(
        NullPointerException.class, () -> HttpsContextFactory.createSslContext(null, null));

    Assertions.assertThrows(
        NullPointerException.class, () -> HttpsContextFactory.createSslContext(badKeyStore, null));

    Assertions.assertThrows(
        Exception.class,
        () -> KeystoreLoader.loadKeystoreAsRawData("src/test/resources/certs/nginx.jks"));

    Assertions.assertThrows(
        NullPointerException.class, () -> HttpsContextFactory.initializeTrustManager(null));

    final var serverData =
        KeystoreLoader.loadKeystoreAsRawData("src/test/resources/certs/nginx.truststore");
    final Keystore serverTruststore = new Keystore(serverData, "password", KeyStoreType.PKCS12);

    Assertions.assertThrows(
        KeystoreException.class,
        () -> HttpsContextFactory.createSslContext(badKeyStore, serverTruststore));
  }

  @Test
  void expectCreateUnsafeSslContextWorksSuccessfully() throws IOException {
    final var certData = KeystoreLoader.loadKeystoreAsRawData(Constants.LAB_DEMIS_11111_P12);
    final Keystore userKeystore =
        new Keystore(certData, Constants.LAB_DEMIS_11111_PASSWORD, KeyStoreType.PKCS12);

    final var serverData =
        KeystoreLoader.loadKeystoreAsRawData("src/test/resources/certs/nginx.truststore");
    final Keystore serverTruststore = new Keystore(serverData, "password", KeyStoreType.JKS);

    // Disable hostname verification
    environment.set(DemisConstants.ENABLE_HOSTNAME_VERIFICATION_ENV_VAR, "false");

    final var context =
        Assertions.assertDoesNotThrow(
            () -> HttpsContextFactory.createSslContext(userKeystore, serverTruststore));
    Assertions.assertNotNull(context);
  }

  @Test
  void expectCreateSslContextWorksSuccessfullyWithEnvVarActive() throws IOException {
    final var certData = KeystoreLoader.loadKeystoreAsRawData(Constants.LAB_DEMIS_11111_P12);
    final Keystore userKeystore =
        new Keystore(certData, Constants.LAB_DEMIS_11111_PASSWORD, KeyStoreType.PKCS12);

    final var serverData =
        KeystoreLoader.loadKeystoreAsRawData("src/test/resources/certs/nginx.truststore");
    final Keystore serverTruststore = new Keystore(serverData, "password", KeyStoreType.JKS);

    // Disable hostname verification
    environment.set(DemisConstants.ENABLE_HOSTNAME_VERIFICATION_ENV_VAR, "true");

    final var context =
        Assertions.assertDoesNotThrow(
            () -> HttpsContextFactory.createSslContext(userKeystore, serverTruststore));
    Assertions.assertNotNull(context);
  }
}
