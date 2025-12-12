package de.gematik.demis.tls;

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

import java.security.cert.X509Certificate;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/** Creates unsafe trust manager to trust all the certificates. */
public final class UnsafeTrustManagerFactory {
  private UnsafeTrustManagerFactory() {}

  /**
   * Returns the array holding the unsafe trustmanager.
   *
   * @return the array
   */
  public static TrustManager[] getUnsafeTrustManagers() {
    return new TrustManager[] {
      new X509TrustManager() {
        @Override
        public X509Certificate[] getAcceptedIssuers() {
          return null; // NOSONAR
        }

        @Override
        public void checkClientTrusted(
            final X509Certificate[] certs, final String authType) { // NOSONAR
        }

        @Override
        public void checkServerTrusted(
            final X509Certificate[] certs, final String authType) { // NOSONAR
        }
      }
    };
  }
}
