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
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.SignServiceIntegrationService;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.config.impl.DefaultConfigurationManager;
import se.idsec.signservice.integration.config.impl.DefaultIntegrationServiceConfiguration;
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
 * Configuration for the SignService integration.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
@Configuration
@EnableScheduling
public class SignServiceIntegrationConfiguration {

  @Autowired
  @Qualifier("signIntegrationBaseUrl")
  private String signIntegrationBaseUrl;

  @Autowired
  private InMemoryIntegrationServiceStateCache integrationServiceCache;

  @Value("${sp.debug-base-uri:}")
  private String debugBaseUri;

  @Autowired
  private MetadataProvider metadataProvider;

  /**
   * Gets the bean representing the base URL for the signature integration client.
   * 
   * @param contextPath
   *          the context path
   * @param baseUri
   *          the base URI for the application
   * @param serverPort
   *          the server port
   * @return the base URL
   */
  @Bean("signIntegrationBaseUrl")
  public String signIntegrationBaseUrl(
      @Value("${server.servlet.context-path}") String contextPath,
      @Value("${sp.base-uri}") String baseUri,
      @Value("${server.port}") int serverPort) {

    StringBuffer sb = new StringBuffer(baseUri);
    if (serverPort != 443) {
      sb.append(":").append(serverPort);
    }
    if (!contextPath.equals("/")) {
      sb.append(contextPath);
    }
    return sb.toString();
  }

  /**
   * Gets the bean for the SignService Integration Service.
   * 
   * @return SignServiceIntegrationService bean
   * @throws Exception
   *           for bean init errors
   */
  @Bean
  public SignServiceIntegrationService signServiceIntegrationService() throws Exception {
    DefaultSignServiceIntegrationService service = new DefaultSignServiceIntegrationService();
    IntegrationServiceConfiguration config = this.integrationServiceConfiguration();
    log.debug("Using configuration: {}", config);
    final DefaultConfigurationManager cfgMgr = new DefaultConfigurationManager(Collections.singletonMap(config.getPolicy(), config));
    service.setConfigurationManager(cfgMgr);
    DefaultSignatureStateProcessor stateProcessor = new DefaultSignatureStateProcessor();
    stateProcessor.setStateCache(this.integrationServiceCache);
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
    XmlSignedDocumentProcessor xmlProcessor = new XmlSignedDocumentProcessor();
    xmlProcessor.setProcessingConfiguration(this.signResponseProcessingConfig());
    processor.setSignedDocumentProcessors(Arrays.asList(xmlProcessor));
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
   * Method that periodically purges expired entries from the cache.
   */
  @Scheduled(initialDelay = 1200000L, fixedDelay = 1200000L)
  public void clearCache() {
    this.integrationServiceCache.clearExpired();
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
    processor.setTbsDocumentProcessors(Arrays.asList(new XmlTbsDocumentProcessor()));
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
  @DependsOn({ "signIntegrationBaseUrl" })
  public IntegrationServiceConfiguration integrationServiceConfiguration() {
    DefaultIntegrationServiceConfiguration config = new DefaultIntegrationServiceConfiguration();
    config.setDefaultReturnUrl(this.signIntegrationBaseUrl + "/sign/response");
    config.setDefaultEncryptionParameters(new OpenSAMLEncryptionParameters());
    config.setSigningCredential(new OpenSAMLSigningCredential(this.signIntegrationCredential().getCredential()));
//    config.setSignServiceCertificates(Arrays.asList(this.signServiceSigningCertificate));
    //config.setTrustAnchors(this.trustAnchors);
    return config;
  }

//  @Bean("signServiceSigningCertificate")
//  public X509Certificate signServiceSigningCertificate(
//      @Value("${signservice.config.sign-service-certificate}") Resource cert) throws Exception {
//    return X509CertificateUtils.decodeCertificate(cert.getInputStream());
//  }

//  @Bean("trustAnchors")
//  public List<X509Certificate> trustAnchors(
//      @Value("${signservice.config.trust-anchors}") List<Resource> certs) throws Exception {
//
//    List<X509Certificate> anchors = new ArrayList<>();
//    for (Resource r : certs) {
//      anchors.add(X509CertificateUtils.decodeCertificate(r.getInputStream()));
//    }
//    return anchors;
//  }

  @Bean("debugReturnUrl")
  public String debugReturnUrl(@Value("${server.servlet.context-path}") String contextPath) {
    return String.format("%s%s/sign/response", this.debugBaseUri.trim(), contextPath.equals("/") ? "" : contextPath);
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
