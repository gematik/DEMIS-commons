package de.gematik.demis.tls;

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

import static de.gematik.demis.DemisConstants.LOG_ERROR_MESSAGE_FORMAT;

import de.gematik.demis.DemisConstants;
import de.gematik.demis.exceptions.KeystoreException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

/** Utility Class defining the TLS Context Factory for the Http Client. */
@Slf4j
public final class HttpsContextFactory {

  private static final TrustManager[] UNSAFE_TRUST_MANAGERS =
      UnsafeTrustManagerFactory.getUnsafeTrustManagers();

  /**
   * Acquires the global keystore lock managed by {@link KeystoreLoader}. Callers that directly use
   * {@link KeystoreLoader} together with {@link KeyManagerFactory#init} should bracket the whole
   * sequence with {@link #lockKeystore()} / {@link #unlockKeystore()} to prevent concurrent PKCS12
   * access.
   */
  public static void lockKeystore() {
    KeystoreLoader.lock();
  }

  /** Releases the global keystore lock previously acquired via {@link #lockKeystore()}. */
  public static void unlockKeystore() {
    KeystoreLoader.unlock();
  }

  private HttpsContextFactory() {}

  /**
   * Creates a {@link SSLContext} object containing Keystore and Truststore to be used.
   *
   * @param clientKeystore the User's keystore
   * @param serverTruststore the truststore containing the server certificate to be trusted
   * @return a {@link SSLContext} object
   * @throws KeystoreException in case of error
   */
  public static SSLContext createSslContext(
      @NonNull final Keystore clientKeystore, @NonNull final Keystore serverTruststore)
      throws KeystoreException {
    // Serialize the entire keystore-load + KeyManagerFactory-init sequence via the central lock
    // in KeystoreLoader.  KeyManagerFactory.init() internally calls KeyStore.getKey() which is
    // also not thread-safe on PKCS12 keystores, so the lock must cover more than just load().
    KeystoreLoader.lock();
    try {
      final KeyStore keystore = KeystoreLoader.load(clientKeystore);
      final KeyManagerFactory keyMgrFactory = resolveKeyManagerFactory(clientKeystore, keystore);

      final KeyStore serverkeystore = KeystoreLoader.load(serverTruststore);
      final TrustManager[] trustManagers = getTrustManagers(serverkeystore);

      final SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
      sslContext.init(keyMgrFactory.getKeyManagers(), trustManagers, null);
      return sslContext;
    } catch (final NoSuchAlgorithmException
        | KeyManagementException
        | KeyStoreException
        | CertificateException
        | IOException e) {
      log.error(LOG_ERROR_MESSAGE_FORMAT, e.getLocalizedMessage(), e);
      throw new KeystoreException(e.getLocalizedMessage());
    } finally {
      KeystoreLoader.unlock();
    }
  }

  /**
   * Resolves the {@link KeyManagerFactory} by trying the effective key password first. If that
   * fails and a separate private-key password was provided, it retries with the keystore password
   * as fallback (resilience against mismatched passwords).
   *
   * @param clientKeystore the keystore configuration holding password information
   * @param keystore the loaded {@link KeyStore} instance
   * @return an initialized {@link KeyManagerFactory}
   * @throws KeystoreException if no password combination succeeds
   */
  private static KeyManagerFactory resolveKeyManagerFactory(
      final Keystore clientKeystore, final KeyStore keystore) throws KeystoreException {
    final String keystorePassword = clientKeystore.getPassword();
    final String privateKeyPassword = clientKeystore.getPrivateKeyPassword();
    // prefer private-key password when present, fallback to keystore password
    final String effectiveKeyPassword =
        privateKeyPassword != null ? privateKeyPassword : keystorePassword;
    try {
      return initializeKeyManager(keystore, effectiveKeyPassword);
    } catch (KeystoreException e) {
      log.warn(
          "Initializing KeyManager with chosen key password failed (will retry with keystore password): {}",
          e.getLocalizedMessage());
      if (privateKeyPassword != null && !privateKeyPassword.equals(keystorePassword)) {
        // retry with keystore password as fallback
        return initializeKeyManager(keystore, keystorePassword);
      }
      log.error(LOG_ERROR_MESSAGE_FORMAT, e.getLocalizedMessage(), e);
      throw new KeystoreException(e);
    }
  }

  /**
   * Creates SSL Parameters for the client.
   *
   * @param enableMutualAuthentication if true, sets the requirement of mTLS
   * @return the {@link SSLParameters} object with hostname verification enabled (HTTPS algorithm)
   */
  public static SSLParameters createSslParameters(final boolean enableMutualAuthentication) {
    return createSslParameters(enableMutualAuthentication, true);
  }

  /**
   * Creates SSL Parameters for the client.
   *
   * <p>When {@code enableHostnameVerification} is {@code false}, the endpoint identification
   * algorithm is set to an empty string, which disables hostname verification in {@link
   * java.net.http.HttpClient} without relying on the internal system property {@code
   * jdk.internal.httpclient.disableHostnameVerification}.
   *
   * @param enableMutualAuthentication if true, sets the requirement of mTLS
   * @param enableHostnameVerification if false, disables hostname verification via the standard
   *     {@link SSLParameters} API
   * @return the configured {@link SSLParameters} object
   */
  public static SSLParameters createSslParameters(
      final boolean enableMutualAuthentication, final boolean enableHostnameVerification) {
    final SSLParameters params = new SSLParameters();
    params.setNeedClientAuth(enableMutualAuthentication);
    // Empty string disables endpoint identification (hostname check) in java.net.http.HttpClient.
    // This is the official public API alternative to the internal system property
    // jdk.internal.httpclient.disableHostnameVerification.
    params.setEndpointIdentificationAlgorithm(enableHostnameVerification ? "HTTPS" : "");
    return params;
  }

  /**
   * Initializes the Keystore Manager containing the user's keystore.
   *
   * @param keystore the user keystore
   * @param privKeyPassword the private key password
   * @return an initialized {@link KeyManagerFactory} object
   * @throws KeystoreException in case of errors
   */
  public static KeyManagerFactory initializeKeyManager(
      @NonNull final KeyStore keystore, final String privKeyPassword) throws KeystoreException {

    try {
      final KeyManagerFactory keyMgrFactory =
          KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
      keyMgrFactory.init(keystore, privKeyPassword.toCharArray());
      return keyMgrFactory;
    } catch (final NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException e) {
      log.error(LOG_ERROR_MESSAGE_FORMAT, e.getLocalizedMessage(), e);
      throw new KeystoreException(e.getLocalizedMessage());
    }
  }

  /**
   * Initializes the Truststore Manager containing the server's certificate.
   *
   * @param truststore the truststore containing server's certificate
   * @return an initialized {@link TrustManagerFactory} object
   * @throws KeystoreException in case of errors
   */
  public static TrustManagerFactory initializeTrustManager(@NonNull final KeyStore truststore)
      throws KeystoreException {
    try {
      final TrustManagerFactory trustManagerFactory =
          TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      trustManagerFactory.init(truststore);
      return trustManagerFactory;
    } catch (final NoSuchAlgorithmException | KeyStoreException e) {
      log.error(LOG_ERROR_MESSAGE_FORMAT, e.getLocalizedMessage(), e);
      throw new KeystoreException(e.getLocalizedMessage());
    }
  }

  private static TrustManager[] getTrustManagers(final KeyStore truststore) {

    if (!isValidationEnabled()) {
      log.warn("Using the Unsafe Trust Manager (Hostname Verification is deactivated)");
      return UNSAFE_TRUST_MANAGERS;
    }
    final TrustManagerFactory trustManagerFactory = initializeTrustManager(truststore);
    return trustManagerFactory.getTrustManagers();
  }

  /**
   * Checks if the environment variable is set and returns its value. If the Variable is not
   * defined, by default the hostname verification is true.
   *
   * @return true by default, otherwise what is defined for the environment variable
   */
  public static boolean isValidationEnabled() {
    if (!System.getenv().containsKey(DemisConstants.ENABLE_HOSTNAME_VERIFICATION_ENV_VAR)) {
      return true;
    }
    return Boolean.parseBoolean(System.getenv(DemisConstants.ENABLE_HOSTNAME_VERIFICATION_ENV_VAR));
  }
}
