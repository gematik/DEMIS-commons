package de.gematik.demis.token.validation;

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

import de.gematik.demis.token.data.KeyStoreConfigParameter;
import java.util.Objects;

@Deprecated(forRemoval = true)
public class KeyStoreConfigParameterValidator {

  private KeyStoreConfigParameterValidator() {}

  public static void validateKeyStoreConfigParameter(
      KeyStoreConfigParameter keyStoreConfigParameter) {

    validateAlias(keyStoreConfigParameter);
    validatePassword(keyStoreConfigParameter);
  }

  private static void validatePassword(KeyStoreConfigParameter keyStoreConfigParameter) {
    if (Objects.isNull(keyStoreConfigParameter.getAuthCertPassword())
        || keyStoreConfigParameter.getAuthCertPassword().isBlank()) {
      throw new IllegalArgumentException(
          "Invalid key store configuration: the auth cert password should not be empty!");
    }
  }

  private static void validateAlias(KeyStoreConfigParameter keyStoreConfigParameter) {
    if (Objects.isNull(keyStoreConfigParameter.getAuthCertAlias())
        || keyStoreConfigParameter.getAuthCertAlias().isBlank()) {
      throw new IllegalArgumentException(
          "Invalid key store configuration: the auth cert alias should not be empty!");
    }
  }
}
