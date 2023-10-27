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

package de.gematik.demis.proxy;

import java.util.Objects;
import lombok.Getter;

/** Defines the Proxy Configurations */
@Getter
public class ProxySettings {
  private final boolean enabled;
  private final String host;
  private final int port;

  public ProxySettings(final boolean enabled, final String host, final String port) {

    this.enabled = Objects.requireNonNull(enabled);
    this.host = Objects.requireNonNull(host);
    this.port = Integer.valueOf(Objects.requireNonNull(port));
  }
}
