package de.gematik.demis.token.data;

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

import de.gematik.demis.tls.Keystore;
import de.gematik.demis.token.data.types.Password;
import java.util.Objects;
import lombok.Getter;

/** Definition of Request Information. */
@Getter
public class RequestParameter {
  private final String idpUrl;
  private final User user;

  public static RequestParameter create(
      final String idpUrl, final String username, final String clientId, final Keystore userCert) {
    return new RequestParameter(
        idpUrl, username, clientId, "secret_client_secret", "password", userCert, null);
  }

  public static RequestParameter create(
      String idpUrl, String username, String clientId, String clientSecret, Keystore userCert) {
    return new RequestParameter(
        idpUrl, username, clientId, clientSecret, "password", userCert, null);
  }

  public static RequestParameter create(
      String idpUrl,
      String username,
      String clientId,
      String clientSecret,
      String grantType,
      Keystore userCert,
      Password password) {
    return new RequestParameter(
        idpUrl, username, clientId, clientSecret, grantType, userCert, password);
  }

  private RequestParameter(
      final String idpUrl,
      final String username,
      final String clientId,
      final String clientSecret,
      final String grantType,
      final Keystore userCert,
      final Password password) {
    this.user = new User(username, clientId, clientSecret, userCert, grantType, password);
    this.idpUrl = Objects.requireNonNull(idpUrl);
  }
}
