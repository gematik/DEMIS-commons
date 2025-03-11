package de.gematik.demis.tls;

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
 * #L%
 */

import static de.gematik.demis.DemisConstants.LOG_ERROR_MESSAGE_FORMAT;

import de.gematik.demis.exceptions.KeystoreException;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Objects;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

/** Utilities to load keystore. */
@Slf4j
public final class KeystoreLoader {
  private KeystoreLoader() {}

  /**
   * Reads the keystore as a byte array, given a file path.
   *
   * @param keystorePath the file or class path used to load the keystore
   * @return the content of the keystore
   * @throws IOException in case of errors
   */
  public static byte[] loadKeystoreAsRawData(final String keystorePath) throws IOException {
    try (final var inputStream = new FileInputStream(keystorePath)) {
      return inputStream.readAllBytes();
    }
  }

  /**
   * Loads a {@link KeyStore} object from a given {@link KeyStore} instance.
   *
   * @param keystore the instance to be loaded ad {@link KeyStore}
   * @return the {@link KeyStore} object
   * @throws KeyStoreException
   * @throws CertificateException
   * @throws IOException
   * @throws NoSuchAlgorithmException
   */
  public static KeyStore load(final Keystore keystore)
      throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
    Objects.requireNonNull(keystore, "requireNonNull keystore");

    final KeyStore keyStore = KeyStore.getInstance(keystore.getType().name());
    keyStore.load(
        new ByteArrayInputStream(keystore.getData()), keystore.getPassword().toCharArray());
    return keyStore;
  }

  public static PrivateKey loadPrivateKey(
      @NonNull final KeyStore keyStore,
      @NonNull final String alias,
      @NonNull final String password) {
    try {
      return (PrivateKey) keyStore.getKey(alias, password.toCharArray());
    } catch (final NullPointerException
        | KeyStoreException
        | NoSuchAlgorithmException
        | UnrecoverableKeyException e) {
      log.error(LOG_ERROR_MESSAGE_FORMAT, e.getLocalizedMessage(), e);
      throw new KeystoreException(e.getLocalizedMessage());
    }
  }
}
