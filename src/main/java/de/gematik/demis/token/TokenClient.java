package de.gematik.demis.token;

/*-
 * #%L
 * DEMIS Commons Library
 * %%
 * Copyright (C) 2025 - 2026 gematik GmbH
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

import com.fasterxml.jackson.core.JsonParser.Feature;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.demis.exceptions.KeystoreException;
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
import java.net.http.HttpClient.Redirect;
import java.net.http.HttpClient.Version;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import javax.net.ssl.SSLContext;
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
      new ObjectMapper().configure(Feature.ALLOW_SINGLE_QUOTES, true);

  /**
   * Cache for {@link SSLContext} instances keyed by a combination of client-keystore data hash and
   * truststore data hash. This avoids repeatedly loading and decrypting the same PKCS12 keystores
   * across parallel test threads, which both improves performance and eliminates the sporadic
   * {@link javax.crypto.BadPaddingException} caused by concurrent PKCS12 provider access.
   */
  private static final ConcurrentHashMap<String, SSLContext> SSL_CONTEXT_CACHE =
      new ConcurrentHashMap<>();

  public TokenClient(@NonNull final Keystore truststore, ProxySettings proxySettings) {
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
    try (final HttpClient client = this.createClient(user)) {
      final HttpRequest request = this.createPostRequest(idpURL, user);
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
      throw new TokenException(e);
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
      throw new TokenException(e);
    }
  }

  private HttpClient createClient(final User user) throws KeystoreException {
    // Use cached SSLContext to avoid redundant keystore loading across parallel threads.
    final SSLContext sslContext = getOrCreateSslContext(user.getKeystore());

    // Hostname verification is controlled via SSLParameters (public API) instead of the internal
    // system property jdk.internal.httpclient.disableHostnameVerification.
    final boolean hostnameVerification = HttpsContextFactory.isValidationEnabled();
    final HttpClient.Builder builder =
        HttpClient.newBuilder()
            .sslContext(sslContext)
            .sslParameters(HttpsContextFactory.createSslParameters(true, hostnameVerification))
            .version(Version.HTTP_1_1)
            .followRedirects(Redirect.ALWAYS)
            .connectTimeout(Duration.ofSeconds(10L));
    if (Objects.nonNull(this.proxySettings) && this.proxySettings.isEnabled()) {
      builder.proxy(
          ProxySelector.of(
              new InetSocketAddress(this.proxySettings.getHost(), this.proxySettings.getPort())));
    }

    return builder.build();
  }

  /**
   * Returns a cached {@link SSLContext} for the given client keystore, creating one if absent. The
   * cache key is derived from the binary content of both the client keystore and the truststore so
   * that identical keystore/truststore combinations share a single SSLContext instance.
   *
   * @param clientKeystore the client keystore to build the SSLContext for
   * @return a (potentially cached) SSLContext
   * @throws KeystoreException if SSLContext creation fails
   */
  private SSLContext getOrCreateSslContext(final Keystore clientKeystore) throws KeystoreException {
    final String cacheKey =
        Arrays.hashCode(clientKeystore.getData())
            + ":"
            + Arrays.hashCode(this.truststore.getData());
    // computeIfAbsent guarantees that the factory is called at most once per key, even under
    // concurrent access – this naturally serializes the expensive keystore-load per unique key.
    try {
      return SSL_CONTEXT_CACHE.computeIfAbsent(
          cacheKey,
          key -> {
            try {
              log.debug("Creating new SSLContext for cache key {}", key);
              return HttpsContextFactory.createSslContext(clientKeystore, this.truststore);
            } catch (KeystoreException e) {
              log.error(LOG_ERROR_MESSAGE_FORMAT, e.getLocalizedMessage(), e);
              throw new TokenException(e);
            }
          });
    } catch (TokenException e) {
      // Unwrap the TokenException thrown from the lambda to propagate as KeystoreException
      throw new KeystoreException(e);
    }
  }

  private HttpRequest createPostRequest(final String idpURL, final User user) {
    final String body = this.createFormUrlEncodedRequest(user);
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
