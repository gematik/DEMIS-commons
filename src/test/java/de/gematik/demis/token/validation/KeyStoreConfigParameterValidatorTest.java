/*
 * Copyright [2023], gematik GmbH
 *
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
 */

package de.gematik.demis.token.validation;

import static de.gematik.demis.enums.KeyStoreType.JKS;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import de.gematik.demis.token.data.KeyStoreConfigParameter;
import java.io.InputStream;
import org.junit.jupiter.api.Test;

class KeyStoreConfigParameterValidatorTest {

  @Test
  void shouldNotThrowAnyException() {

    KeyStoreConfigParameter keyStoreConfigParameter =
        KeyStoreConfigParameter.builder()
            .authCertKeyStoreType(JKS)
            .authCertKeyStore(InputStream.nullInputStream())
            .authCertAlias("someAlias")
            .authCertPassword("somepassword")
            .trustStore(InputStream.nullInputStream())
            .trustStorePassword("somepassword2")
            .build();
    assertDoesNotThrow(
        () ->
            KeyStoreConfigParameterValidator.validateKeyStoreConfigParameter(
                keyStoreConfigParameter));
  }

  @Test
  void shouldThrowExceptionForEmptyAlias() {

    KeyStoreConfigParameter keyStoreConfigParameter =
        KeyStoreConfigParameter.builder()
            .authCertKeyStoreType(JKS)
            .authCertKeyStore(InputStream.nullInputStream())
            .authCertAlias("")
            .authCertPassword("somepassword")
            .trustStore(InputStream.nullInputStream())
            .trustStorePassword("somepassword2")
            .build();

    // TODO welche Variante wollen wir nutzen?

    IllegalArgumentException illegalArgumentException =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                KeyStoreConfigParameterValidator.validateKeyStoreConfigParameter(
                    keyStoreConfigParameter));
    assertEquals(
        "Invalid key store configuration: the auth cert alias should not be empty!",
        illegalArgumentException.getMessage());

    assertThatThrownBy(
            () ->
                KeyStoreConfigParameterValidator.validateKeyStoreConfigParameter(
                    keyStoreConfigParameter))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Invalid key store configuration: the auth cert alias should not be empty!");
  }

  @Test
  void shouldThrowExceptionForEmptyPassword() {

    KeyStoreConfigParameter keyStoreConfigParameter =
        KeyStoreConfigParameter.builder()
            .authCertKeyStoreType(JKS)
            .authCertKeyStore(InputStream.nullInputStream())
            .authCertAlias("someAlias")
            .authCertPassword("")
            .trustStore(InputStream.nullInputStream())
            .trustStorePassword("somepassword2")
            .build();
    assertThatThrownBy(
            () ->
                KeyStoreConfigParameterValidator.validateKeyStoreConfigParameter(
                    keyStoreConfigParameter))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Invalid key store configuration: the auth cert password should not be empty!");
  }
}
