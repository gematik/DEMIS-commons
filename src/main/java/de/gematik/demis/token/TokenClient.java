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
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik,
 * find details in the "Readme" file.
 * #L%
 */

import static de.gematik.demis.DemisConstants.LOG_ERROR_MESSAGE_FORMAT;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.demis.exceptions.TokenException;
import de.gematik.demis.proxy.ProxySettings;
import de.gematik.demis.tls.HttpsContextFactory;
import de.gematik.demis.tls.Keystore;
import de.gematik.demis.token.data.RequestParameter;
import de.gematik.demis.token.data.User;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

/**
 * Client to retrieve a JWT Token from a remove server. It requires the remote Token URL, a valid
 * {@link Keystore} truststore containing the server certificate to be trusted and a {@link
 * ProxySettings} object containing optional Proxy Configurations
 */
@Slf4j
public class TokenClient {
  /** The truststore used for establishing the connection against the OIDC Server. */
  @NonNull private final Keystore truststore;

  /** The Proxy Settings for establishing the connection. */
  private final ProxySettings proxySettings;

  /** Jackson Object Mapper parse. */
  private final ObjectMapper objectMapper =
      new ObjectMapper().enable(JsonParser.Feature.ALLOW_SINGLE_QUOTES);

  public TokenClient(@NonNull final Keystore truststore, final ProxySettings proxySettings) {
    this.truststore = truststore;
    this.proxySettings = proxySettings;
  }

  /**
   * Retrieves the Raw Response for a particular user.
   *
   * @param idpURL idp full url
   * @param user a structure containing the information relative to request.
   * @return the whole response from the OIDC Server as String.
   */
  private String fetchAsJson(@NonNull final String idpURL, @NonNull final User user) {

    log.info("Retrieving token from URL {}", idpURL);
    try {
      final var client = createClient(user);
      final var request = createPostRequest(idpURL, user);
      final HttpResponse<String> response =
          client.send(request, HttpResponse.BodyHandlers.ofString());
      if (response.statusCode() >= 400) {
        log.warn(response.body());
        throw new TokenException("Got Response with code: " + response.statusCode());
      }
      log.debug("Got Body {}", response.body());
      return response.body();
    } catch (final Exception e) { // NOSONAR
      log.error(LOG_ERROR_MESSAGE_FORMAT, e.getLocalizedMessage(), e);
      throw new TokenException(e.getLocalizedMessage());
    }
  }

  /**
   * Retrieves the parsed response for a particular user.
   *
   * @param requestParameter a structure containing the information relative to user.
   * @return the whole parsed response from the OIDC Server.
   */
  public TokenResponse fetch(@NonNull final RequestParameter requestParameter) {
    return fetch(requestParameter.getIdpUrl(), requestParameter.getUser());
  }

  public TokenResponse fetch(@NonNull final String idpURL, @NonNull final User user) {
    try {
      return objectMapper.readValue(fetchAsJson(idpURL, user), TokenResponse.class);
    } catch (final JsonProcessingException e) {
      log.error(LOG_ERROR_MESSAGE_FORMAT, e.getLocalizedMessage(), e);
      throw new TokenException(e.getLocalizedMessage());
    }
  }

  private HttpClient createClient(final User user) {
    final var builder =
        HttpClient.newBuilder()
            .sslContext(HttpsContextFactory.createSslContext(user.getKeystore(), truststore))
            .sslParameters(HttpsContextFactory.createSslParameters(true))
            .version(HttpClient.Version.HTTP_1_1)
            .followRedirects(HttpClient.Redirect.ALWAYS)
            .connectTimeout(Duration.ofSeconds(10));

    if (Objects.nonNull(proxySettings) && proxySettings.isEnabled()) {
      builder.proxy(
          ProxySelector.of(
              new InetSocketAddress(proxySettings.getHost(), proxySettings.getPort())));
    }

    return builder.build();
  }

  private HttpRequest createPostRequest(final String idpURL, final User user) {
    final var body = createFormUrlEncodedRequest(user);
    return HttpRequest.newBuilder()
        .uri(URI.create(idpURL))
        .POST(HttpRequest.BodyPublishers.ofString(body))
        .header("Accept", "application/json")
        .header("Content-type", "application/x-www-form-urlencoded")
        .build();
  }

  private String createFormUrlEncodedRequest(final User user) {

    final Map<String, String> parameters = new HashMap<>();
    parameters.put("username", user.getUsername());
    parameters.put("client_id", user.getClientId());
    parameters.put("client_secret", user.getClientSecret());
    parameters.put("grant_type", user.getGrantType());
    user.getPassword().ifPresent(password -> parameters.put("password", password.getValue()));

    return parameters.entrySet().stream()
        .map(e -> e.getKey() + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
        .collect(Collectors.joining("&"));
  }
}
