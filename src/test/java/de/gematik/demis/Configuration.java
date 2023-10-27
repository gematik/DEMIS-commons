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

import java.util.Properties;

/** Singleton holding application properties */
class Configuration {

  private final Properties properties;
  private static Configuration instance = null;

  /** Private constructor */
  private Configuration() {
    this.properties = new Properties();
    try {
      properties.load(
          Thread.currentThread()
              .getContextClassLoader()
              .getResourceAsStream(Constants.PROPERTIES_PATH));
    } catch (Exception ex) {
      throw new RuntimeException("Could not load properties", ex);
    }
  }

  private static synchronized void createInstance() {
    if (instance == null) {
      instance = new Configuration();
    }
  }

  /** Get the properties instance. Uses singleton pattern */
  public static Configuration getInstance() {
    // Uses singleton pattern to guarantee the creation of only one instance
    if (instance == null) {
      createInstance();
    }
    return instance;
  }

  /** Get a property of the property file */
  public String getProperty(String key) {
    String result = null;
    if (key != null && !key.trim().isEmpty()) {
      result = this.properties.getProperty(key);
    }
    return result;
  }

  /** Override the clone method to ensure the "unique instance" requirement of this class */
  public Object clone() throws CloneNotSupportedException {
    throw new CloneNotSupportedException();
  }
}
