/*
 * Copyright 2019-2025 IDsec Solutions AB
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
package se.idsec.signservice.integration.testbase;

import org.junit.jupiter.api.BeforeAll;

import se.idsec.signservice.integration.SignServiceIntegrationServiceInitializer;
import se.swedenconnect.opensaml.sweid.xmlsec.config.SwedishEidSecurityConfiguration;

/**
 * Test base.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public abstract class TestBase {

  /**
   * Initializes the OpenSAML library.
   *
   * @throws Exception
   *           for init errors
   */
  @BeforeAll
  public static void initialize() throws Exception {
    SignServiceIntegrationServiceInitializer.initialize(new SwedishEidSecurityConfiguration());
  }

}
