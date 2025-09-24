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
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 * #L%
 */

import de.gematik.demis.token.data.ProxyConfiguration;

@Deprecated(forRemoval = true)
public class ProxyConfigurationValidator {

  private ProxyConfigurationValidator() {}

  public static void validate(ProxyConfiguration proxyConfiguration) {
    var port = proxyConfiguration.getPort();
    var host = proxyConfiguration.getHost();

    validateHost(host);
    validatePort(port);
  }

  private static void validatePort(int port) {
    if (port < -1 || port > 65535) {
      throw new IllegalArgumentException(
          String.format(
              "Invalid ProxyConfiguration: the given port number must be between 0-65535 or -1 if no port should be used, but was '%d'",
              port));
    }
  }

  private static void validateHost(String host) {
    if (host.isBlank()) {
      throw new IllegalArgumentException("Invalid ProxyConfiguration: Host must not be empty!");
    }
  }
}
