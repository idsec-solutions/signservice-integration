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
package se.idsec.signservice.integration.config.impl;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import se.idsec.signservice.integration.authentication.SignerIdentityAttribute;
import se.idsec.signservice.integration.certificate.CertificateAttributeMapping;
import se.idsec.signservice.integration.certificate.CertificateType;
import se.idsec.signservice.integration.certificate.RequestedCertificateAttribute;
import se.idsec.signservice.integration.certificate.RequestedCertificateAttributeType;
import se.idsec.signservice.integration.certificate.SigningCertificateRequirements;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.security.impl.DefaultEncryptionParameters;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.factory.KeyStoreBuilder;

import java.security.KeyStore;
import java.util.HashMap;
import java.util.Map;

/**
 * Test cases for DefaultConfigurationManager.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefaultConfigurationManagerTest {

  private final DefaultIntegrationServiceConfiguration coreConfig;

  public DefaultConfigurationManagerTest() throws Exception {

    final KeyStore keyStore = KeyStoreBuilder.builder()
        .location("classpath:signing.jks")
        .type("JKS")
        .password("secret")
        .build();

    final KeyStoreCredential signingCred = new KeyStoreCredential(keyStore, "default", "secret".toCharArray());

    this.coreConfig = DefaultIntegrationServiceConfiguration.builder()
        .policy("default")
        .defaultSignRequesterID("defaultSignRequesterID")
        .defaultReturnUrl("https://example.com")
        .defaultSignatureAlgorithm("sha256")
        .signServiceID("signServiceID")
        .defaultDestinationUrl("https://example.com/dest")
        .defaultCertificateRequirements(
            SigningCertificateRequirements.builder()
                .certificateType(CertificateType.PKC)
                .attributeMapping(
                    CertificateAttributeMapping.builder()
                        .destination(
                            RequestedCertificateAttribute.builder()
                                .name("dummy")
                                .type(RequestedCertificateAttributeType.RDN)
                                .build())
                        .source(SignerIdentityAttribute.createBuilder()
                            .type(SignerIdentityAttribute.SAML_TYPE)
                            .name("urn:xxx")
                            .build())
                        .build())
                .build())
        .defaultEncryptionParameters(new DefaultEncryptionParameters())
        .signingCredential(signingCred)
        .signServiceCertificate(signingCred.getCertificate() /* Just need a cert */)
        .trustAnchor(signingCred.getCertificate() /* Just need a cert */)
        .build();
  }

  @Test
  public void testMerge() {

    final Map<String, IntegrationServiceConfiguration> map = new HashMap<>();

    final DefaultIntegrationServiceConfiguration c1 = this.coreConfig.toBuilder()
        .policy("default")
        .defaultSignRequesterID("Kalle")
        .defaultAuthnContextRef("loa3")
        .defaultSignatureAlgorithm("sha256")
        .build();
    map.put(c1.getPolicy(), c1.toBuilder().build() /* make copy */);

    final DefaultIntegrationServiceConfiguration c3 = DefaultIntegrationServiceConfiguration.builder()
        .policy("no3")
        .parentPolicy("no2")
        .defaultSignRequesterID("Kalle1")
        .defaultSignatureAlgorithm("sha1")
        .build();
    map.put(c3.getPolicy(), c3.toBuilder().build());

    final DefaultIntegrationServiceConfiguration c2 = DefaultIntegrationServiceConfiguration.builder()
        .policy("no2")
        .parentPolicy("default")
        .defaultAuthnContextRef("loa2")
        .build();
    map.put(c2.getPolicy(), c2.toBuilder().build());

    final DefaultConfigurationManager mgr = new DefaultConfigurationManager(map);

    final IntegrationServiceConfiguration c2b = mgr.getConfiguration("no2");
    Assertions.assertNull(c2b.getParentPolicy());
    Assertions.assertEquals("loa2", c2b.getDefaultAuthnContextRef());
    Assertions.assertEquals("Kalle", c2b.getDefaultSignRequesterID());
    Assertions.assertEquals("sha256", c2b.getDefaultSignatureAlgorithm());

    final IntegrationServiceConfiguration c3b = mgr.getConfiguration("no3");
    Assertions.assertNull(c3b.getParentPolicy());
    Assertions.assertEquals("loa2", c3b.getDefaultAuthnContextRef());
    Assertions.assertEquals("Kalle1", c3b.getDefaultSignRequesterID());
    Assertions.assertEquals("sha1", c3b.getDefaultSignatureAlgorithm());

    Assertions.assertEquals(c1.toString(), mgr.getConfiguration("default").toString());
  }

  @Test
  public void testMergeCircular() {
    final Map<String, IntegrationServiceConfiguration> map = new HashMap<>();

    final DefaultIntegrationServiceConfiguration c1 = this.coreConfig.toBuilder()
        .policy("default")
        .defaultSignRequesterID("Kalle")
        .build();
    map.put(c1.getPolicy(), c1.toBuilder().build() /* make copy */);

    final DefaultIntegrationServiceConfiguration c2 = this.coreConfig.toBuilder()
        .policy("no2")
        .parentPolicy("no3")
        .build();
    map.put(c2.getPolicy(), c2.toBuilder().build());

    final DefaultIntegrationServiceConfiguration c3 = this.coreConfig.toBuilder()
        .policy("no3")
        .parentPolicy("no4")
        .build();
    map.put(c3.getPolicy(), c3.toBuilder().build());

    final DefaultIntegrationServiceConfiguration c4 = this.coreConfig.toBuilder()
        .policy("no3")
        .parentPolicy("no2")
        .build();
    map.put(c4.getPolicy(), c4.toBuilder().build());

    Assertions.assertThrows(IllegalArgumentException.class, () -> new DefaultConfigurationManager(map));
  }

  @Test
  public void testMergeMissingParent() {
    final Map<String, IntegrationServiceConfiguration> map = new HashMap<>();

    final DefaultIntegrationServiceConfiguration c1 = this.coreConfig.toBuilder()
        .policy("default")
        .defaultSignRequesterID("Kalle")
        .build();
    map.put(c1.getPolicy(), c1.toBuilder().build() /* make copy */);

    final DefaultIntegrationServiceConfiguration c2 = this.coreConfig.toBuilder()
        .policy("no2")
        .parentPolicy("no3")
        .build();
    map.put(c2.getPolicy(), c2.toBuilder().build());

    Assertions.assertThrows(IllegalArgumentException.class, () -> new DefaultConfigurationManager(map));
  }

}
