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

package de.gematik.demis;

public class DemisConstants {

  public static final String AUTHORIZATION_HEADER_NAME = "Authorization";
  public static final String ATTRIBUTE_VERIFIED_JWT = ":Verified-JWT";
  public static final String ATTRIBUTE_ROLE_CONTAINER = ":RoleContainer";
  public static final String LOG_ERROR_MESSAGE_FORMAT = "Got error: {}";
  public static final String ENABLE_HOSTNAME_VERIFICATION_ENV_VAR = "ENABLE_HOSTNAME_VERIFICATION";

  private DemisConstants() {}
}
