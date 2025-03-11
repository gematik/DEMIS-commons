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

import static de.gematik.demis.enums.ProxyProtocolEnum.HTTP;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.demis.token.data.ProxyConfiguration;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

@Disabled
class ProxyConfigurationValidatorTest {

  private static final String PROXY_HOST = "192.168.110.10";

  @SuppressWarnings("unused")
  private static Stream<Arguments> provideInvalidConfiguration() {
    return Stream.of(
        Arguments.of(
            new ProxyConfiguration(HTTP, "", 1234, "user", null),
            "Invalid ProxyConfiguration: Host must not be empty!"),
        Arguments.of(
            new ProxyConfiguration(HTTP, "   ", 1234, "user", null),
            "Invalid ProxyConfiguration: Host must not be empty!"),
        Arguments.of(
            new ProxyConfiguration(HTTP, PROXY_HOST, -100, "user", null),
            "Invalid ProxyConfiguration: the given port number must be between 0-65535 or -1 if no port should be used, but was '-100'"),
        Arguments.of(
            new ProxyConfiguration(HTTP, PROXY_HOST, 65536, "user", null),
            "Invalid ProxyConfiguration: the given port number must be between 0-65535 or -1 if no port should be used, but was '65536'"));
  }

  @SuppressWarnings("unused")
  private static Stream<Arguments> provideValidConfiguration() {
    return Stream.of(
        Arguments.of(new ProxyConfiguration(HTTP, "host", 1234, "user", "pw")),
        Arguments.of(new ProxyConfiguration(HTTP, "host", 1234, "", "")),
        Arguments.of(new ProxyConfiguration(HTTP, "host", 1234, "user", null)),
        Arguments.of(new ProxyConfiguration(HTTP, "host", -1, "user", null)),
        Arguments.of(new ProxyConfiguration(HTTP, "host", -1, "", "")));
  }

  @ParameterizedTest(name = "[{index}] {0}, expected message: {1}")
  @MethodSource("provideInvalidConfiguration")
  void testValidateThrowsException(ProxyConfiguration proxyConfiguration, String expectedMessage) {
    assertThatThrownBy(() -> ProxyConfigurationValidator.validate(proxyConfiguration))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage(expectedMessage);
  }

  @ParameterizedTest(name = "[{index}] {0}")
  @MethodSource("provideValidConfiguration")
  void testValidateIsFine(ProxyConfiguration proxyConfiguration) {
    Assertions.assertDoesNotThrow(() -> ProxyConfigurationValidator.validate(proxyConfiguration));
  }
}
