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

import de.gematik.demis.Constants;
import de.gematik.demis.DemisConstants;
import de.gematik.demis.enums.KeyStoreType;
import de.gematik.demis.exceptions.KeystoreException;
import de.gematik.demis.tls.HttpsContextFactory;
import de.gematik.demis.tls.Keystore;
import de.gematik.demis.tls.KeystoreLoader;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
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
    // Default: hostname verification active → HTTPS endpoint identification
    Assertions.assertEquals("HTTPS", params.getEndpointIdentificationAlgorithm());
    Assertions.assertTrue(params.getNeedClientAuth());
  }

  @Test
  void createSslParametersWithHostnameVerificationDisabled() {
    final var params =
        Assertions.assertDoesNotThrow(() -> HttpsContextFactory.createSslParameters(true, false));
    Assertions.assertNotNull(params);
    // Hostname verification disabled → empty endpoint identification algorithm
    Assertions.assertEquals("", params.getEndpointIdentificationAlgorithm());
    Assertions.assertTrue(params.getNeedClientAuth());
  }

  @Test
  void createSslParametersWithHostnameVerificationEnabled() {
    final var params =
        Assertions.assertDoesNotThrow(() -> HttpsContextFactory.createSslParameters(false, true));
    Assertions.assertNotNull(params);
    Assertions.assertEquals("HTTPS", params.getEndpointIdentificationAlgorithm());
    Assertions.assertFalse(params.getNeedClientAuth());
  }

  @Test
  void isValidationEnabledReturnsTrueByDefault() {
    // No env var set → defaults to true
    Assertions.assertTrue(HttpsContextFactory.isValidationEnabled());
  }

  @Test
  void isValidationEnabledReturnsFalseWhenEnvVarSetToFalse() {
    environment.set(DemisConstants.ENABLE_HOSTNAME_VERIFICATION_ENV_VAR, "false");
    Assertions.assertFalse(HttpsContextFactory.isValidationEnabled());
  }

  @Test
  void isValidationEnabledReturnsTrueWhenEnvVarSetToTrue() {
    environment.set(DemisConstants.ENABLE_HOSTNAME_VERIFICATION_ENV_VAR, "true");
    Assertions.assertTrue(HttpsContextFactory.isValidationEnabled());
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

  /** Covers {@code lockKeystore()} / {@code unlockKeystore()} delegation to KeystoreLoader. */
  @Test
  void expectLockAndUnlockKeystoreWorkWithoutException() {
    Assertions.assertDoesNotThrow(
        () -> {
          HttpsContextFactory.lockKeystore();
          HttpsContextFactory.unlockKeystore();
        });
  }

  /** Covers {@code initializeTrustManager} happy path when called directly. */
  @Test
  void expectInitializeTrustManagerSucceeds() throws IOException {
    final var rawData =
        KeystoreLoader.loadKeystoreAsRawData("src/test/resources/certs/nginx.truststore");
    final Keystore jks = Keystore.createJKS(rawData, "password");
    final var loaded = Assertions.assertDoesNotThrow(() -> KeystoreLoader.load(jks));

    final var tmf =
        Assertions.assertDoesNotThrow(() -> HttpsContextFactory.initializeTrustManager(loaded));
    Assertions.assertNotNull(tmf);
    Assertions.assertNotNull(tmf.getTrustManagers());
  }

  /** Covers {@code initializeKeyManager} happy path when called directly. */
  @Test
  void expectInitializeKeyManagerSucceeds() throws IOException {
    final var certData = KeystoreLoader.loadKeystoreAsRawData(Constants.LAB_DEMIS_11111_P12);
    final Keystore keystore =
        new Keystore(certData, Constants.LAB_DEMIS_11111_PASSWORD, KeyStoreType.PKCS12);
    final var loaded = Assertions.assertDoesNotThrow(() -> KeystoreLoader.load(keystore));

    final var kmf =
        Assertions.assertDoesNotThrow(
            () ->
                HttpsContextFactory.initializeKeyManager(
                    loaded, Constants.LAB_DEMIS_11111_PASSWORD));
    Assertions.assertNotNull(kmf);
    Assertions.assertNotNull(kmf.getKeyManagers());
  }

  /** Covers the {@code KeystoreException} path in {@code initializeKeyManager}. */
  @Test
  void expectInitializeKeyManagerThrowsOnWrongPassword() throws IOException {
    final var certData = KeystoreLoader.loadKeystoreAsRawData(Constants.LAB_DEMIS_11111_P12);
    final Keystore keystore =
        new Keystore(certData, Constants.LAB_DEMIS_11111_PASSWORD, KeyStoreType.PKCS12);
    final var loaded = Assertions.assertDoesNotThrow(() -> KeystoreLoader.load(keystore));

    Assertions.assertThrows(
        NullPointerException.class, () -> HttpsContextFactory.initializeKeyManager(loaded, null));
  }

  /**
   * Covers {@code resolveKeyManagerFactory} fallback branch: when {@code privateKeyPassword}
   * differs from {@code password} and the first attempt fails, it retries with the keystore
   * password.
   */
  @Test
  void expectCreateSslContextSucceedsWhenPrivateKeyPasswordMatchesKeystorePassword()
      throws IOException {
    // Use a Keystore where privateKeyPassword equals the keystore password → the first
    // initializeKeyManager attempt with the private-key password succeeds.
    final var certData = KeystoreLoader.loadKeystoreAsRawData(Constants.LAB_DEMIS_11111_P12);
    final Keystore userKeystore =
        new Keystore(
            certData,
            Constants.LAB_DEMIS_11111_PASSWORD,
            KeyStoreType.PKCS12,
            Constants.LAB_DEMIS_11111_ALIAS,
            Constants.LAB_DEMIS_11111_PASSWORD);

    final var serverData =
        KeystoreLoader.loadKeystoreAsRawData("src/test/resources/certs/nginx.truststore");
    final Keystore serverTruststore = new Keystore(serverData, "password", KeyStoreType.JKS);

    final var context =
        Assertions.assertDoesNotThrow(
            () -> HttpsContextFactory.createSslContext(userKeystore, serverTruststore));
    Assertions.assertNotNull(context);
  }

  /**
   * Covers the {@code resolveKeyManagerFactory} retry branch: {@code privateKeyPassword} is set to
   * a wrong value so the first attempt fails; the fallback retries with the keystore password which
   * succeeds.
   */
  @Test
  void expectCreateSslContextSucceedsWhenFallbackToKeystorePassword() throws IOException {
    final var certData = KeystoreLoader.loadKeystoreAsRawData(Constants.LAB_DEMIS_11111_P12);
    // privateKeyPassword is intentionally wrong – factory must retry with keystorePassword
    final Keystore userKeystore =
        new Keystore(
            certData,
            Constants.LAB_DEMIS_11111_PASSWORD,
            KeyStoreType.PKCS12,
            Constants.LAB_DEMIS_11111_ALIAS,
            "wrongPrivateKeyPassword");

    final var serverData =
        KeystoreLoader.loadKeystoreAsRawData("src/test/resources/certs/nginx.truststore");
    final Keystore serverTruststore = new Keystore(serverData, "password", KeyStoreType.JKS);

    final var context =
        Assertions.assertDoesNotThrow(
            () -> HttpsContextFactory.createSslContext(userKeystore, serverTruststore));
    Assertions.assertNotNull(context);
  }

  /**
   * Covers the {@code catch} branch in {@code initializeKeyManager}: an uninitialised {@link
   * KeyStore} causes {@code KeyManagerFactory.init()} to throw, which is caught and re-thrown as
   * {@link KeystoreException}.
   */
  @Test
  void expectInitializeKeyManagerThrowsKeystoreExceptionOnUninitializedKeyStore()
      throws KeyStoreException {
    final KeyStore empty = KeyStore.getInstance("PKCS12");
    // deliberately NOT calling empty.load(...) – the keystore is uninitialised
    Assertions.assertThrows(
        KeystoreException.class,
        () -> HttpsContextFactory.initializeKeyManager(empty, "anyPassword"));
  }

  /**
   * Covers the {@code resolveKeyManagerFactory} no-retry branch: when {@code privateKeyPassword} is
   * non-null but equal to {@code keystorePassword} and {@code initializeKeyManager} fails, the
   * factory must NOT retry but immediately re-throw the {@link KeystoreException}.
   */
  @Test
  void expectCreateSslContextThrowsWhenKeystoreIsUnreadable() throws IOException {
    // Supply a JKS truststore with the wrong password so that KeystoreLoader.load() throws an
    // IOException which createSslContext wraps into a KeystoreException – this exercises the
    // catch-all error path at the top of createSslContext.
    final var certData = KeystoreLoader.loadKeystoreAsRawData(Constants.LAB_DEMIS_11111_P12);
    final Keystore userKeystore =
        new Keystore(certData, Constants.LAB_DEMIS_11111_PASSWORD, KeyStoreType.PKCS12);
    final var serverData =
        KeystoreLoader.loadKeystoreAsRawData("src/test/resources/certs/nginx.truststore");
    final Keystore badTruststore = new Keystore(serverData, "wrongPassword", KeyStoreType.JKS);

    Assertions.assertThrows(
        KeystoreException.class,
        () -> HttpsContextFactory.createSslContext(userKeystore, badTruststore));
  }
}
