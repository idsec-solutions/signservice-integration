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
package se.idsec.signservice.integration.spring.actuator;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import se.idsec.signservice.integration.config.ConfigurationManager;
import se.idsec.signservice.integration.config.impl.DefaultConfigurationManager;
import se.idsec.signservice.integration.document.pdf.PdfSignedDocumentProcessor;
import se.idsec.signservice.integration.document.xml.XmlSignedDocumentProcessor;
import se.idsec.signservice.integration.process.SignResponseProcessingConfig;
import se.idsec.signservice.integration.process.SignResponseProcessor;
import se.idsec.signservice.integration.process.impl.DefaultSignResponseProcessor;
import se.idsec.signservice.integration.process.impl.DefaultSignerAssertionInfoProcessor;
import se.idsec.signservice.integration.process.impl.SignerAssertionInfoProcessor;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.factory.PkiCredentialFactory;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Autoconfiguration for setting up a SignService Integration Service.
 *
 * @author Martin Lindström
 */
@AutoConfiguration
@EnableConfigurationProperties(IntegrationServiceConfigurationProperties.class)
public class IntegrationServiceAutoConfiguration {

  private final IntegrationServiceConfigurationProperties properties;

  private final PkiCredentialFactory credentialFactory;

  public IntegrationServiceAutoConfiguration(final IntegrationServiceConfigurationProperties properties,
      final PkiCredentialFactory credentialFactory) {
    this.properties = properties;
    this.credentialFactory = credentialFactory;
  }

  @Bean
  ConfigurationManager configurationManager(
      @Qualifier("SignService.External.Policies") final Map<String, PolicyConfigurationProperties> externalPolicies)
      throws Exception {

    final Map<String, PolicyConfigurationProperties> policies = new HashMap<>(externalPolicies);
    policies.putAll(this.properties.getConfig());

    for (final Map.Entry<String, PolicyConfigurationProperties> pe : policies.entrySet()) {
      final PolicyConfigurationProperties policy = pe.getValue();
      if (policy.getSigningCredentialConfig() != null) {
        final PkiCredential credential = this.credentialFactory.createCredential(policy.getSigningCredentialConfig());
        policy.setSigningCredential(credential);
        policy.setSigningCredentialConfig(null);
      }
    }

    final DefaultConfigurationManager cfgMgr = new DefaultConfigurationManager(policies);
    Optional.ofNullable(this.properties.getDefaultPolicyName()).ifPresent(cfgMgr::setDefaultPolicyName);

    return cfgMgr;
  }

  @Bean
  SignResponseProcessingConfig signResponseProcessingConfig() {
    return this.properties.getResponse();
  }

  @ConditionalOnMissingBean
  @Bean
  SignerAssertionInfoProcessor signerAssertionInfoProcessor(
      final SignResponseProcessingConfig signResponseProcessingConfig) {
    final DefaultSignerAssertionInfoProcessor p = new DefaultSignerAssertionInfoProcessor();
    p.setProcessingConfig(signResponseProcessingConfig);
    p.afterPropertiesSet();
    return p;
  }

  @ConditionalOnMissingBean
  @Bean
  SignResponseProcessor signResponseProcessor(final SignResponseProcessingConfig signResponseProcessingConfig,
      final SignerAssertionInfoProcessor signerAssertionInfoProcessor) throws Exception {
    final DefaultSignResponseProcessor processor = new DefaultSignResponseProcessor();
    processor.setProcessingConfiguration(signResponseProcessingConfig);

    final XmlSignedDocumentProcessor xmlProcessor = new XmlSignedDocumentProcessor();
    xmlProcessor.setProcessingConfiguration(signResponseProcessingConfig);

    final PdfSignedDocumentProcessor pdfProcessor = new PdfSignedDocumentProcessor();
    pdfProcessor.setProcessingConfiguration(signResponseProcessingConfig);

    processor.setSignedDocumentProcessors(Arrays.asList(xmlProcessor, pdfProcessor));
    processor.setSignerAssertionInfoProcessor(signerAssertionInfoProcessor);
    processor.afterPropertiesSet();
    return processor;
  }

}
