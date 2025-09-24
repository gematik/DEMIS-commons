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
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 * #L%
 */

import de.gematik.demis.Constants;
import de.gematik.demis.enums.KeyStoreType;
import java.io.IOException;
import java.security.KeyStore;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class KeystoreLoaderTest {

  @Test
  void expectKeystoreLoadsFromStructureSuccessfully() throws IOException {
    final var rawData = KeystoreLoader.loadKeystoreAsRawData(Constants.LAB_DEMIS_11111_P12);
    final Keystore keystore = Keystore.createPKCS12(rawData, Constants.LAB_DEMIS_11111_PASSWORD);

    final KeyStore keyStore = Assertions.assertDoesNotThrow(() -> KeystoreLoader.load(keystore));
    Assertions.assertNotNull(keyStore);
    Assertions.assertTrue(
        Assertions.assertDoesNotThrow(
            () -> keyStore.containsAlias(Constants.LAB_DEMIS_11111_ALIAS)));
  }

  @Test
  void expectKeystoreLoadsFromPathSuccessfully() throws IOException {
    final var rawData = KeystoreLoader.loadKeystoreAsRawData(Constants.LAB_DEMIS_11111_P12);
    final Keystore pkcs12 = Keystore.createPKCS12(rawData, Constants.LAB_DEMIS_11111_PASSWORD);
    final var keyStore = Assertions.assertDoesNotThrow(() -> KeystoreLoader.load(pkcs12));
    Assertions.assertNotNull(keyStore);
    Assertions.assertTrue(
        Assertions.assertDoesNotThrow(
            () -> keyStore.containsAlias(Constants.LAB_DEMIS_11111_ALIAS)));
  }

  @Test
  void expectTrustStoreLoadsSuccessfully() throws IOException {
    final var rawData =
        KeystoreLoader.loadKeystoreAsRawData("src/test/resources/certs/nginx.truststore");
    final Keystore jks = Keystore.createJKS(rawData, "password");
    final var truststore = Assertions.assertDoesNotThrow(() -> KeystoreLoader.load(jks));
    Assertions.assertNotNull(truststore);
  }

  @Test
  void expectPrivateKeyReadSuccessfully() throws IOException {
    final var rawData = KeystoreLoader.loadKeystoreAsRawData(Constants.LAB_DEMIS_11111_P12);
    final Keystore userInput =
        new Keystore(
            rawData,
            Constants.LAB_DEMIS_11111_PASSWORD,
            KeyStoreType.PKCS12,
            Constants.LAB_DEMIS_11111_ALIAS,
            Constants.LAB_DEMIS_11111_PASSWORD);

    final var keystore = Assertions.assertDoesNotThrow(() -> KeystoreLoader.load(userInput));
    final var privateKey =
        KeystoreLoader.loadPrivateKey(keystore, userInput.getAlias(), userInput.getPassword());
    Assertions.assertNotNull(privateKey);
  }

  @Test
  void expectFailureOnInvalidInput() {
    Assertions.assertThrows(NullPointerException.class, () -> KeystoreLoader.load(null));
  }

  @Test
  void expectFailureOnInvalidPrivateKey() throws IOException {
    final var rawData = KeystoreLoader.loadKeystoreAsRawData(Constants.LAB_DEMIS_11111_P12);
    final Keystore userInput =
        new Keystore(
            rawData,
            Constants.LAB_DEMIS_11111_PASSWORD,
            KeyStoreType.PKCS12,
            Constants.LAB_DEMIS_11111_ALIAS,
            Constants.LAB_DEMIS_11111_PASSWORD);

    final var keystore = Assertions.assertDoesNotThrow(() -> KeystoreLoader.load(userInput));
    Assertions.assertThrows(
        NullPointerException.class, () -> KeystoreLoader.loadPrivateKey(keystore, null, null));

    Assertions.assertThrows(
        Exception.class, () -> KeystoreLoader.loadPrivateKey(keystore, userInput.getAlias(), ""));
  }
}
