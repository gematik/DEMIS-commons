package de.gematik.demis;

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

public class Constants {
  public static final String PROPERTIES_PATH = "adapter-app.properties";
  private static final String RESOURCES_PATH = "src/test/resources";

  public static final String LAB_DEMIS_11111_P12 =
      RESOURCES_PATH + Configuration.getInstance().getProperty(Properties.IDP_LAB_AUTHCERTKEYSTORE);
  public static final String LAB_DEMIS_11111_PASSWORD =
      Configuration.getInstance().getProperty(Properties.IDP_LAB_AUTHCERTPASSWORD);
  public static final String LAB_DEMIS_11111_ALIAS =
      Configuration.getInstance().getProperty(Properties.IDP_LAB_AUTHCERTALIAS);
}
