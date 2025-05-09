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
package se.idsec.signservice.integration.app.config;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import se.idsec.signservice.integration.ExtendedSignServiceIntegrationService;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.config.impl.DefaultConfigurationManager;
import se.idsec.signservice.integration.config.impl.DefaultIntegrationServiceConfiguration;
import se.idsec.signservice.integration.document.pdf.DefaultPdfSignaturePagePreparator;
import se.idsec.signservice.integration.document.pdf.PdfSignedDocumentProcessor;
import se.idsec.signservice.integration.document.pdf.PdfTbsDocumentProcessor;
import se.idsec.signservice.integration.document.xml.XmlSignedDocumentProcessor;
import se.idsec.signservice.integration.document.xml.XmlTbsDocumentProcessor;
import se.idsec.signservice.integration.impl.DefaultSignServiceIntegrationService;
import se.idsec.signservice.integration.process.SignRequestProcessor;
import se.idsec.signservice.integration.process.SignResponseProcessor;
import se.idsec.signservice.integration.process.impl.DefaultSignRequestProcessor;
import se.idsec.signservice.integration.process.impl.DefaultSignResponseProcessor;
import se.idsec.signservice.integration.security.impl.OpenSAMLEncryptionParameters;
import se.idsec.signservice.integration.security.impl.OpenSAMLIdpMetadataResolver;
import se.idsec.signservice.integration.signmessage.impl.DefaultSignMessageProcessor;
import se.idsec.signservice.integration.state.impl.DefaultSignatureStateProcessor;
import se.idsec.signservice.integration.state.impl.InMemoryIntegrationServiceStateCache;
import se.swedenconnect.opensaml.saml2.metadata.provider.MetadataProvider;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.factory.PkiCredentialFactoryBean;

import java.util.Arrays;
import java.util.Collections;

/**
 * Configuration for the SignService integration when using the Java API (not REST).
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Configuration
@ConditionalOnProperty(name = "signservice.rest.enabled", havingValue = "false", matchIfMissing = true)
@EnableConfigurationProperties(IntegrationServiceConfigurationProperties.class)
public class JavaApiSignServiceIntegrationConfiguration {

  private final MetadataProvider metadataProvider;

  private final IntegrationServiceConfigurationProperties properties;

  public JavaApiSignServiceIntegrationConfiguration(
      final IntegrationServiceConfigurationProperties properties, final MetadataProvider metadataProvider) {
    this.properties = properties;
    this.metadataProvider = metadataProvider;
  }

  /**
   * Gets the bean for the service configuration.
   *
   * @return IntegrationServiceConfiguration bean
   */
  @Bean
  public IntegrationServiceConfiguration integrationServiceConfiguration(
      @Qualifier("signIntegrationBaseUrl") final String signIntegrationBaseUrl) throws Exception {
    final DefaultIntegrationServiceConfiguration config = this.properties.getConfig();
    config.setDefaultReturnUrl(signIntegrationBaseUrl + "/sign/response");
    config.setDefaultEncryptionParameters(new OpenSAMLEncryptionParameters());
    config.setSigningCredential(this.signIntegrationCredential());
    return config;
  }

  @Bean
  ExtendedSignServiceIntegrationService signServiceIntegrationService(final IntegrationServiceConfiguration config,
      final SignResponseProcessor signResponseProcessor)
      throws Exception {

    final DefaultSignServiceIntegrationService service = new DefaultSignServiceIntegrationService();
    service.setPdfSignaturePagePreparator(new DefaultPdfSignaturePagePreparator());
    final DefaultConfigurationManager cfgMgr =
        new DefaultConfigurationManager(Collections.singletonMap(config.getPolicy(), config));
    cfgMgr.setDefaultPolicyName(this.properties.getDefaultPolicyName());
    service.setConfigurationManager(cfgMgr);
    final DefaultSignatureStateProcessor stateProcessor = new DefaultSignatureStateProcessor();
    stateProcessor.setStateCache(null);
    stateProcessor.setConfigurationManager(cfgMgr);
    stateProcessor.afterPropertiesSet();
    service.setSignatureStateProcessor(stateProcessor);
    service.setSignRequestProcessor(this.signRequestProcessor());
    service.setSignResponseProcessor(signResponseProcessor);
    return service;
  }

  /**
   * Gets the bean for the integration service cache.
   *
   * @return the cache
   */
  @Bean
  InMemoryIntegrationServiceStateCache integrationServiceCache() {
    return new InMemoryIntegrationServiceStateCache();
  }

  /**
   * Creates a sign request processor.
   *
   * @return a SignRequestProcessor bean
   * @throws Exception for bean init errors
   */
  @Bean
  SignRequestProcessor signRequestProcessor() throws Exception {
    final DefaultSignRequestProcessor processor = new DefaultSignRequestProcessor();
    processor.setTbsDocumentProcessors(Arrays.asList(new XmlTbsDocumentProcessor(), new PdfTbsDocumentProcessor()));
    processor.setDefaultVersion("1.4");
    final DefaultSignMessageProcessor signMessageProcessor = new DefaultSignMessageProcessor();
    signMessageProcessor.setIdpMetadataResolver(
        new OpenSAMLIdpMetadataResolver(this.metadataProvider.getMetadataResolver()));
    signMessageProcessor.afterPropertiesSet();
    processor.setSignMessageProcessor(signMessageProcessor);
    return processor;
  }

  @Bean("signIntegrationCredential")
  PkiCredential signIntegrationCredential() throws Exception {
    final PkiCredentialFactoryBean factory = new PkiCredentialFactoryBean(this.properties.getCredential());
    factory.afterPropertiesSet();
    return factory.getObject();
  }

}
