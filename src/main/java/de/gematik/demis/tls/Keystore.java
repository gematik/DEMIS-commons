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

package de.gematik.demis.tls;

import de.gematik.demis.enums.KeyStoreType;
import java.util.Objects;
import lombok.Getter;

/** Structure holding keystore/truststore information. */
@Getter
public class Keystore {
  /** The binary content of the keystore */
  private final byte[] data;

  /** The password for the file */
  private final String password;

  /** The type (one between JKS or PKCS12) */
  private final KeyStoreType type;

  /** The Alias for the certificate/key stored in the file */
  private final String alias;

  /** The password for the private key (if different from keystore password) */
  private final String privateKeyPassword;

  /**
   * Creates an Object without alias (typically a TrustStore)
   *
   * @param data
   * @param password
   * @param type
   */
  public Keystore(final byte[] data, final String password, final KeyStoreType type) {
    this(data, password, type, null, null);
  }

  /**
   * Creates an Object without alias and a password for the key different from the file one (without
   * alias means that there's only one key-pair in the keystore).
   *
   * @param data
   * @param password
   * @param type
   * @param privateKeyPassword
   */
  public Keystore(
      final byte[] data,
      final String password,
      final KeyStoreType type,
      final String privateKeyPassword) {
    this(data, password, type, null, privateKeyPassword);
  }

  /**
   * Default constructor.
   *
   * @param data
   * @param password
   * @param type
   * @param alias
   * @param privateKeyPassword
   */
  public Keystore(
      final byte[] data,
      final String password,
      final KeyStoreType type,
      final String alias,
      final String privateKeyPassword) {
    this.data = Objects.requireNonNull(data);
    this.password = Objects.requireNonNull(password);
    this.type = Objects.requireNonNull(type);
    this.alias = alias;
    this.privateKeyPassword = privateKeyPassword;
  }

  public static Keystore createJKS(
      final byte[] data, final String password, final String alias, String privateKeyPassword) {
    return new Keystore(data, password, KeyStoreType.JKS, privateKeyPassword, alias);
  }

  public static Keystore createJKS(final byte[] data, final String password) {
    return new Keystore(data, password, KeyStoreType.JKS, null, null);
  }

  public static Keystore createPKCS12(final byte[] data, final String password, String alias) {
    return new Keystore(data, password, KeyStoreType.PKCS12, alias, null);
  }

  public static Keystore createPKCS12(final byte[] data, final String password) {
    return new Keystore(data, password, KeyStoreType.PKCS12, null, null);
  }
}
