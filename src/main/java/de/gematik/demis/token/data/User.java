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
 * For additional notes and disclaimer from gematik and in case of changes by gematik,
 * find details in the "Readme" file.
 * #L%
 */

import de.gematik.demis.tls.Keystore;
import de.gematik.demis.token.data.types.Password;
import java.util.Objects;
import java.util.Optional;
import lombok.Getter;

/** Definition of User Information. */
@Getter
public class User {
  private final String username;
  private final String clientId;
  private final String clientSecret;
  private final Keystore keystore;
  private final String grantType;
  private final Password password;

  /**
   * Creates a user with grant type "password" as default.
   *
   * @param username
   * @param clientId
   * @param clientSecret
   * @param keystore
   */
  public User(
      final String username,
      final String clientId,
      final String clientSecret,
      final Keystore keystore) {
    this(username, clientId, clientSecret, keystore, "password", null);
  }

  /**
   * Constructor with default client Secret and grant type.
   *
   * @param username
   * @param clientId
   * @param keystore
   */
  public User(final String username, final String clientId, final Keystore keystore) {
    this(username, clientId, "secret_client_secret", keystore, "password", null);
  }

  /**
   * Default Constructor.
   *
   * @param username
   * @param clientId
   * @param clientSecret
   * @param keystore
   * @param grantType
   */
  public User(
      String username, String clientId, String clientSecret, Keystore keystore, String grantType) {
    this(username, clientId, clientSecret, keystore, grantType, null);
  }

  /**
   * All Args Constructor.
   *
   * @param username
   * @param clientId
   * @param clientSecret
   * @param keystore
   * @param grantType
   * @param password optional, only for password flow
   */
  public User(
      String username,
      String clientId,
      String clientSecret,
      Keystore keystore,
      String grantType,
      Password password) {
    this.username = Objects.requireNonNull(username);
    this.clientId = Objects.requireNonNull(clientId);
    this.clientSecret = Objects.requireNonNull(clientSecret);
    this.keystore = Objects.requireNonNull(keystore);
    this.grantType = Objects.requireNonNull(grantType);
    this.password = password;
  }

  public Optional<Password> getPassword() {
    return Optional.ofNullable(password);
  }
}
