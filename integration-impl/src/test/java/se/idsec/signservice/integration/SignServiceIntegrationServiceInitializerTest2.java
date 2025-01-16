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
package se.idsec.signservice.integration;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.XMLRuntimeException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.xmlsec.EncryptionConfiguration;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;

import se.swedenconnect.opensaml.sweid.xmlsec.config.SwedishEidSecurityConfiguration;

/**
 * Test cases for {@link SignServiceIntegrationServiceInitializer}.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class SignServiceIntegrationServiceInitializerTest2 {

  @Test
  public void testInitSecurityConfig() throws Exception {

    if (SignServiceIntegrationServiceInitializer.isInitialized()) {
      return;
    }

    // Try creating OpenSAML object. Should not be possible.
    Assertions.assertThrows(XMLRuntimeException.class, () -> {
      XMLObjectSupport.buildXMLObject(Issuer.DEFAULT_ELEMENT_NAME);
    });

    SignServiceIntegrationServiceInitializer.initialize(new SwedishEidSecurityConfiguration());

    // Now, it should work
    XMLObjectSupport.buildXMLObject(Issuer.DEFAULT_ELEMENT_NAME);

    // The SAML2IntSecurityConfiguration prefers AES-CBC before AES-GCM. Assert that.
    //
    EncryptionConfiguration encConfig = ConfigurationService.get(EncryptionConfiguration.class);
    int cbcPos = encConfig.getDataEncryptionAlgorithms().indexOf(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);
    int gcmPos = encConfig.getDataEncryptionAlgorithms().indexOf(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128_GCM);
    Assertions.assertTrue(cbcPos < gcmPos);
  }

}
