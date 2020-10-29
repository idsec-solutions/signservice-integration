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
package se.idsec.signservice.integration.app.config;

import java.util.Arrays;
import java.util.Collections;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import lombok.Setter;
import se.idsec.signservice.integration.ExtendedSignServiceIntegrationService;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.config.impl.DefaultConfigurationManager;
import se.idsec.signservice.integration.config.impl.DefaultIntegrationServiceConfiguration;
import se.idsec.signservice.integration.document.pdf.PdfSignedDocumentProcessor;
import se.idsec.signservice.integration.document.pdf.PdfTbsDocumentProcessor;
import se.idsec.signservice.integration.document.pdf.signpage.DefaultPdfSignaturePagePreparator;
import se.idsec.signservice.integration.document.xml.XmlSignedDocumentProcessor;
import se.idsec.signservice.integration.document.xml.XmlTbsDocumentProcessor;
import se.idsec.signservice.integration.impl.DefaultSignServiceIntegrationService;
import se.idsec.signservice.integration.process.SignRequestProcessor;
import se.idsec.signservice.integration.process.SignResponseProcessingConfig;
import se.idsec.signservice.integration.process.SignResponseProcessor;
import se.idsec.signservice.integration.process.impl.DefaultSignRequestProcessor;
import se.idsec.signservice.integration.process.impl.DefaultSignResponseProcessor;
import se.idsec.signservice.integration.security.impl.OpenSAMLEncryptionParameters;
import se.idsec.signservice.integration.security.impl.OpenSAMLIdpMetadataResolver;
import se.idsec.signservice.integration.signmessage.impl.DefaultSignMessageProcessor;
import se.idsec.signservice.integration.state.impl.DefaultSignatureStateProcessor;
import se.idsec.signservice.integration.state.impl.InMemoryIntegrationServiceStateCache;
import se.idsec.signservice.security.sign.impl.OpenSAMLSigningCredential;
import se.litsec.opensaml.saml2.metadata.provider.MetadataProvider;
import se.swedenconnect.eid.sp.config.SpCredential;

/**
 * Configuration for the SignService integration when using the Java API (not REST).
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Configuration
@ConditionalOnProperty(name = "signservice.rest.enabled", havingValue = "false", matchIfMissing = true)
public class JavaApiSignServiceIntegrationConfiguration {

  @Autowired
  @Setter
  private MetadataProvider metadataProvider;
  
  @Value("${signservice.default-policy-name:default}")
  @Setter
  private String policyName;

  /**
   * Gets the bean for the SignService Integration Service.
   * 
   * @return SignServiceIntegrationService bean
   * @throws Exception
   *           for bean init errors
   */
  @Bean
  public ExtendedSignServiceIntegrationService signServiceIntegrationService(final IntegrationServiceConfiguration config) throws Exception {
    DefaultSignServiceIntegrationService service = new DefaultSignServiceIntegrationService();
    service.setPdfSignaturePagePreparator(new DefaultPdfSignaturePagePreparator());
    final DefaultConfigurationManager cfgMgr = new DefaultConfigurationManager(Collections.singletonMap(config.getPolicy(), config));
    cfgMgr.setDefaultPolicyName(this.policyName);
    service.setConfigurationManager(cfgMgr);
    DefaultSignatureStateProcessor stateProcessor = new DefaultSignatureStateProcessor();
    stateProcessor.setStateCache(null);
    stateProcessor.setConfigurationManager(cfgMgr);
    stateProcessor.afterPropertiesSet();
    service.setSignatureStateProcessor(stateProcessor);
    service.setSignRequestProcessor(this.signRequestProcessor());
    service.setSignResponseProcessor(this.signResponseProcessor());
    return service;
  }

  @Bean
  public SignResponseProcessor signResponseProcessor() throws Exception {
    DefaultSignResponseProcessor processor = new DefaultSignResponseProcessor();
    processor.setProcessingConfiguration(this.signResponseProcessingConfig());
    final XmlSignedDocumentProcessor xmlProcessor = new XmlSignedDocumentProcessor();
    xmlProcessor.setProcessingConfiguration(this.signResponseProcessingConfig());
    final PdfSignedDocumentProcessor pdfProcessor = new PdfSignedDocumentProcessor();
    pdfProcessor.setProcessingConfiguration(this.signResponseProcessingConfig());
    processor.setSignedDocumentProcessors(Arrays.asList(xmlProcessor, pdfProcessor));
    processor.afterPropertiesSet();
    return processor;
  }

  @Bean
  @ConfigurationProperties(prefix = "signservice.response.config")
  public SignResponseProcessingConfig signResponseProcessingConfig() {
    return new SignResponseProcessingConfig();
  }

  /**
   * Gets the bean for the integration service cache.
   * 
   * @return the cache
   */
  @Bean
  public InMemoryIntegrationServiceStateCache integrationServiceCache() {
    return new InMemoryIntegrationServiceStateCache();
  }

  /**
   * Creates a sign request processor.
   * 
   * @return a SignRequestProcessor bean
   * @throws Exception
   *           for bean init errors
   */
  @Bean
  public SignRequestProcessor signRequestProcessor() throws Exception {
    DefaultSignRequestProcessor processor = new DefaultSignRequestProcessor();
    processor.setTbsDocumentProcessors(Arrays.asList(new XmlTbsDocumentProcessor(), new PdfTbsDocumentProcessor()));
    DefaultSignMessageProcessor signMessageProcessor = new DefaultSignMessageProcessor();
    signMessageProcessor.setIdpMetadataResolver(new OpenSAMLIdpMetadataResolver(this.metadataProvider.getMetadataResolver()));
    signMessageProcessor.afterPropertiesSet();
    processor.setSignMessageProcessor(signMessageProcessor);
    return processor;
  }

  /**
   * Gets the bean for the service configuration.
   * 
   * @return IntegrationServiceConfiguration bean
   */
  @Bean
  @ConfigurationProperties(prefix = "signservice.config")
  public IntegrationServiceConfiguration integrationServiceConfiguration(
      @Qualifier("signIntegrationBaseUrl") final String signIntegrationBaseUrl) {
    DefaultIntegrationServiceConfiguration config = new DefaultIntegrationServiceConfiguration();
    config.setDefaultReturnUrl(signIntegrationBaseUrl + "/sign/response");
    config.setDefaultEncryptionParameters(new OpenSAMLEncryptionParameters());
    config.setSigningCredential(new OpenSAMLSigningCredential(this.signIntegrationCredential().getCredential()));
    return config;
  }

  /**
   * Gets the signing credential that the SignService Integration service uses.
   * 
   * @return a SpCredential bean
   */
  @Bean("signIntegrationCredential")
  @ConfigurationProperties(prefix = "signservice.credential")
  public SpCredential signIntegrationCredential() {
    return new SpCredential();
  }

}
