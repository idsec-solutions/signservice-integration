/*
 * Copyright 2019-2020 IDsec Solutions AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.idsec.signservice.integration;

import java.security.AccessController;
import java.security.PrivilegedAction;

import lombok.extern.slf4j.Slf4j;
import se.litsec.swedisheid.opensaml.xmlsec.config.SwedishEidSecurityConfiguration;
import se.swedenconnect.opensaml.OpenSAMLInitializer;
import se.swedenconnect.opensaml.OpenSAMLSecurityDefaultsConfig;
import se.swedenconnect.opensaml.OpenSAMLSecurityExtensionConfig;
import se.swedenconnect.opensaml.xmlsec.config.DefaultSecurityConfiguration;
import se.swedenconnect.opensaml.xmlsec.config.SAML2IntSecurityConfiguration;
import se.swedenconnect.opensaml.xmlsec.config.SecurityConfiguration;

/**
 * The SignService Integration library uses Apache xmlsec and OpenSAML. These libraries need to be initialized before
 * they can be used. This class provides the {@link #initialize()} and {@link #initialize(SecurityConfiguration)}
 * methods for initializing of these libraries.
 * <p>
 * <b>Note:</b> Make sure to initialize the library the first thing you do in your application. Below an example of how
 * a Spring Boot application best initializes the library is presented:
 * </p>
 * 
 * <pre>
 * &#64;Component
 * &#64;Order(Ordered.HIGHEST_PRECEDENCE)
 * public class SignServiceIntegrationInitComponent {
 * 
 *   public SignServiceIntegrationInitComponent() throws Exception {
 *     SignServiceIntegrationServiceInitializer.initialize(
 *       new SwedishEidSecurityConfiguration());
 *   }
 * }
 * </pre>
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class SignServiceIntegrationServiceInitializer {

  /** Flag that tells if the library has been initialized. */
  private static boolean initialized = false;

  /**
   * Initializes Apache xmlsec and OpenSAML with default algorithm settings.
   * 
   * @throws Exception
   *           for initialization errors
   */
  public synchronized static void initialize() throws Exception {
    initialize(null);
  }

  /**
   * Initializes Apache and OpenSAML with the algorithm settings provided by the supplied OpenSAML security settings.
   * Possible security settings comprises of:
   * <ul>
   * <li>{@link DefaultSecurityConfiguration} - OpenSAML's default configuration.</li>
   * <li>{@link SAML2IntSecurityConfiguration} - Security defaults according to Kantara's
   * <a href="https://kantarainitiative.github.io/SAMLprofiles/saml2int.html">SAML2Int specification</a>.</li>
   * <li>{@link SwedishEidSecurityConfiguration} - Security defaults according to the Swedish eID Framework, see
   * <a href="docs.swedenconnect.se">https://docs.swedenconnect.se</a>.</li>
   * </ul>
   * 
   * @param securityConfiguration
   *          the OpenSAML security configuration to apply
   * @throws Exception
   *           for initialization errors
   */
  public synchronized static void initialize(final SecurityConfiguration securityConfiguration) throws Exception {

    if (initialized) {
      log.debug("SignService Integration Service has already been initialized");
      return;
    }

    // First of all, before initializing Apache xmlsec, we make sure that no chunked Base64 string
    // are produced. They end with CRLF, and XML serializing will escape CR with in some cases leads
    // to signature validation errors (.Net software etc).
    //
    log.info("Setting system property 'org.apache.xml.security.ignoreLineBreaks' to true");
    AccessController.doPrivileged(
      (PrivilegedAction<String>) () -> System.setProperty("org.apache.xml.security.ignoreLineBreaks", "true"));

    // Initialize OpenSAML (Apache xmlsec will be initialized by OpenSAML).
    //
    final SecurityConfiguration openSamlConf = securityConfiguration != null ? securityConfiguration : new DefaultSecurityConfiguration();
    log.info("Initializing OpenSAML with security configuration '{}'", openSamlConf.getClass().getName());
    OpenSAMLInitializer.getInstance()
      .initialize(
        new OpenSAMLSecurityDefaultsConfig(openSamlConf),
        new OpenSAMLSecurityExtensionConfig());

    initialized = true;
    log.debug("SignService Integration Service was successfully initialized");
  }

  /**
   * Predicate that tells if the SignService Integration library has been initialized.
   * 
   * @return true if the library has been initialized, and false otherwise
   */
  public static boolean isInitialized() {
    return initialized;
  }

  // Hidden constructor
  private SignServiceIntegrationServiceInitializer() {
  }

}
