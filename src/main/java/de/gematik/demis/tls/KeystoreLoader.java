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

import de.gematik.demis.enums.KeyStoreType;
import de.gematik.demis.exceptions.KeystoreException;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Thread-safe utility class for loading {@link KeyStore} instances and extracting private keys.
 *
 * <p>This is a local override of the class provided by {@code demis-commons}. It shadows the
 * original on the classpath because it resides in the same package ({@code de.gematik.demis.tls})
 * and the project's own classes are loaded before dependency JARs.
 */
@Slf4j
public final class KeystoreLoader {

  private static final String BOUNCY_CASTLE_PROVIDER = BouncyCastleProvider.PROVIDER_NAME;

  /**
   * Global lock that serializes all keystore load / key-extraction operations. This prevents
   * concurrent threads from hitting the non-thread-safe internals of the JDK's SunJCE PKCS12
   * provider (which manifests as a sporadic {@code BadPaddingException}).
   */
  private static final ReentrantLock LOCK = new ReentrantLock();

  static {
    // Register BouncyCastle as an additional provider so it can be requested explicitly by name
    // for PKCS12 keystores (see createKeyStoreInstance). We intentionally do NOT insert it at
    // position 1: doing so makes the JDK's KeyStoreDelegator for JKS delegate to BouncyCastle's
    // PKCS12 engine, which then fails with "keystore password was incorrect" on native JKS files.
    final Provider existing = Security.getProvider(BOUNCY_CASTLE_PROVIDER);
    if (existing == null) {
      Security.addProvider(new BouncyCastleProvider());
      log.info("KeystoreLoader: Registered BouncyCastleProvider as additional security provider");
    }
  }

  private KeystoreLoader() {
    // utility class
  }

  /**
   * Acquires the global keystore lock. Callers that combine {@link #load(Keystore)} with follow-up
   * operations on the returned {@link KeyStore} (e.g. {@link KeyStore#getKey} via {@link
   * javax.net.ssl.KeyManagerFactory#init}) should bracket the entire sequence with {@link #lock()}
   * / {@link #unlock()} to prevent concurrent PKCS12 access.
   *
   * <p>The lock is reentrant, so calling {@link #load(Keystore)} while holding the lock is safe.
   */
  public static void lock() {
    LOCK.lock();
  }

  /** Releases the global keystore lock previously acquired via {@link #lock()}. */
  public static void unlock() {
    LOCK.unlock();
  }

  /**
   * Reads a keystore file from disk as raw bytes.
   *
   * @param keystorePath the file-system path to the keystore file
   * @return the raw byte content of the file
   * @throws IOException if reading fails
   */
  public static byte[] loadKeystoreAsRawData(final String keystorePath) throws IOException {
    try (final var inputStream = new FileInputStream(keystorePath)) {
      return inputStream.readAllBytes();
    }
  }

  /**
   * Loads a {@link KeyStore} from the binary data held in the given {@link Keystore} value object.
   *
   * <p>For PKCS12 keystores the BouncyCastle provider is used explicitly when available, because it
   * is thread-safe. The entire operation is guarded by a lock to prevent concurrent access issues
   * in any provider.
   *
   * @param keystore the keystore value object containing type, data, and password
   * @return a loaded {@link KeyStore} instance
   * @throws KeyStoreException if the keystore type is not supported
   * @throws CertificateException if any certificate in the keystore could not be loaded
   * @throws IOException if there is an I/O or format problem with the keystore data
   * @throws NoSuchAlgorithmException if the algorithm used to check the integrity is not available
   */
  public static KeyStore load(final Keystore keystore)
      throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
    Objects.requireNonNull(keystore, "keystore must not be null");

    LOCK.lock();
    try (final var inputStream = new ByteArrayInputStream(keystore.getData())) {
      final KeyStore ks = createKeyStoreInstance(keystore.getType());
      ks.load(inputStream, keystore.getPassword().toCharArray());
      return ks;
    } finally {
      LOCK.unlock();
    }
  }

  /**
   * Extracts a {@link PrivateKey} from an already-loaded {@link KeyStore}.
   *
   * <p>The operation is guarded by the same lock as {@link #load(Keystore)} to ensure that no
   * concurrent key-extraction can collide with keystore loading.
   *
   * @param keyStore the loaded keystore
   * @param alias the alias of the private-key entry
   * @param password the password protecting the private key
   * @return the private key
   * @throws KeystoreException if the key cannot be retrieved
   */
  public static PrivateKey loadPrivateKey(
      @NonNull final KeyStore keyStore,
      @NonNull final String alias,
      @NonNull final String password) {

    if (password.isEmpty()) {
      throw new KeystoreException("Private key password must not be empty");
    }

    LOCK.lock();
    try {
      return (PrivateKey) keyStore.getKey(alias, password.toCharArray());
    } catch (final NullPointerException
        | KeyStoreException
        | NoSuchAlgorithmException
        | UnrecoverableKeyException e) {
      log.error(LOG_ERROR_MESSAGE_FORMAT, e.getLocalizedMessage(), e);
      throw new KeystoreException(e);
    } finally {
      LOCK.unlock();
    }
  }

  // ---- internal helpers ----

  /** Creates a {@link KeyStore} instance, preferring BouncyCastle for PKCS12 keystores. */
  private static KeyStore createKeyStoreInstance(final KeyStoreType type) throws KeyStoreException {
    if (type == KeyStoreType.PKCS12 && Security.getProvider(BOUNCY_CASTLE_PROVIDER) != null) {
      try {
        return KeyStore.getInstance(type.name(), BOUNCY_CASTLE_PROVIDER);
      } catch (final NoSuchProviderException e) {
        log.warn(
            "BouncyCastle provider not available for PKCS12, falling back to default provider", e);
      }
    }
    return KeyStore.getInstance(type.name());
  }
}
