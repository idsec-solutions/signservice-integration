/*
 * Copyright 2019 IDsec Solutions AB
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

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnore;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.Singular;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.certificate.SigningCertificateRequirements;
import se.idsec.signservice.integration.config.IntegrationServiceDefaultConfiguration;
import se.idsec.signservice.integration.config.SigningCredential;
import se.idsec.signservice.integration.core.Extension;
import se.idsec.signservice.integration.document.pdf.PdfSignatureImageTemplate;
import se.idsec.signservice.integration.security.EncryptionParameters;

/**
 * Default implementation of the {@code IntegrationServiceDefaultConfiguration} interface.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
@Builder
@ToString(exclude = { "signingCredentials" })
public class DefaultIntegrationServiceConfiguration implements IntegrationServiceDefaultConfiguration {

  @Setter
  private String policy;
  
  @Setter
  private String defaultSignRequesterID;
  
  @Setter
  private String defaultReturnUrl;
  
  @Setter
  private String defaultSignatureAlgorithm;
  
  @Setter
  private String signServiceID;
  
  @Setter
  private String defaultDestinationUrl;
  
  @Setter
  private SigningCertificateRequirements signingCertificateRequirements;
  
  @Setter
  @Singular
  private List<PdfSignatureImageTemplate> pdfSignatureImageTemplates;
  
  @Setter
  private boolean stateless;
  
  @Setter
  private EncryptionParameters defaultEncryptionParameters;
    
  @JsonIgnore
  @Getter
  @Setter
  private SigningCredential signingCredentials;
  
  @Setter
  private Extension extension;
  
  /** {@inheritDoc} */
  @Override
  public String getPolicy() {
    return this.policy;
  }

  /** {@inheritDoc} */
  @Override
  public String getDefaultSignRequesterID() {
    return this.defaultSignRequesterID;
  }

  /** {@inheritDoc} */
  @Override
  public String getDefaultReturnUrl() {
    return this.defaultReturnUrl;
  }

  /** {@inheritDoc} */
  @Override
  public String getDefaultSignatureAlgorithm() {
    return this.defaultSignatureAlgorithm;
  }

  /** {@inheritDoc} */
  @Override
  public String getSignServiceID() {
    return this.signServiceID;
  }

  /** {@inheritDoc} */
  @Override
  public String getDefaultDestinationUrl() {
    return this.defaultDestinationUrl;
  }

  /** {@inheritDoc} */
  @Override
  public SigningCertificateRequirements getDefaultCertificateRequirements() {
    return this.signingCertificateRequirements;
  }
  
  /** {@inheritDoc} */
  @Override
  public List<PdfSignatureImageTemplate> getPdfSignatureImageTemplates() {
    return this.pdfSignatureImageTemplates;
  }  

  /** {@inheritDoc} */
  @Override
  public boolean isStateless() {
    return this.stateless;
  }

  /** {@inheritDoc} */
  @Override
  public EncryptionParameters getDefaultEncryptionParameters() {
    return this.defaultEncryptionParameters;
  }

  /** {@inheritDoc} */
  @Override
  public String getSignatureCertificate() {
    X509Certificate cert = this.signingCredentials != null ? this.signingCredentials.getSigningCertificate() : null;
    if (cert == null) {
      return null;
    }
    try {
      return Base64.getEncoder().encodeToString(cert.getEncoded());
    }
    catch (CertificateEncodingException e) {
      log.error("Failed to encode signing certificate", e);
      return null;
    }
  }

  @Override
  public Extension getExtension() {
    return this.extension;
  }

}
