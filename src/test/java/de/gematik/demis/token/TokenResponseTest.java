package de.gematik.demis.token;

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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/** Test to cover the Sonar Quality gates */
class TokenResponseTest {

  @Test
  void testSettersAndGetters() {
    final var tokenResponse = new TokenResponse();
    tokenResponse.setAccessToken("");
    tokenResponse.setExpiresIn(10);
    tokenResponse.setNotBeforePolicy(0);
    tokenResponse.setRefreshExpiresIn(1);
    tokenResponse.setRefreshToken("");
    tokenResponse.setScope("test");
    tokenResponse.setSessionState("");
    tokenResponse.setTokenType("token");

    Assertions.assertEquals("", tokenResponse.getAccessToken());
    Assertions.assertEquals(10, tokenResponse.getExpiresIn());
    Assertions.assertEquals(0, tokenResponse.getNotBeforePolicy());
    Assertions.assertEquals(1, tokenResponse.getRefreshExpiresIn());
    Assertions.assertEquals("", tokenResponse.getRefreshToken());
    Assertions.assertEquals("test", tokenResponse.getScope());
    Assertions.assertEquals("", tokenResponse.getSessionState());
    Assertions.assertEquals("token", tokenResponse.getTokenType());

    Assertions.assertNotEquals(new TokenResponse(), tokenResponse);
    Assertions.assertNotEquals("", tokenResponse.toString());
    Assertions.assertNotEquals(0, tokenResponse.hashCode());
  }
}
