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
package se.idsec.signservice.integration.config.impl;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import org.springframework.util.StringUtils;

import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonIgnore;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.Singular;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.authentication.AuthnRequirements;
import se.idsec.signservice.integration.certificate.SigningCertificateRequirements;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.config.IntegrationServiceDefaultConfiguration;
import se.idsec.signservice.integration.core.Extension;
import se.idsec.signservice.integration.core.ObjectBuilder;
import se.idsec.signservice.integration.document.pdf.PdfSignatureImageTemplate;
import se.idsec.signservice.integration.document.pdf.VisiblePdfSignatureRequirement;
import se.idsec.signservice.integration.security.EncryptionParameters;
import se.idsec.signservice.security.sign.SigningCredential;

/**
 * Default implementation of the {@code IntegrationServiceDefaultConfiguration} interface.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
@ToString(exclude = { "signingCredential", "signServiceCertificates", "trustAnchors" })
public class DefaultIntegrationServiceConfiguration implements IntegrationServiceConfiguration {

  /**
   * The integration policy name for which this configuration applies.
   * 
   * @param policy
   *          the policy identifier
   */
  @Getter
  @Setter
  private String policy;

  /**
   * If several policies are created where most settings are the same, the {@code parentPolicy} can be used to inherit
   * values from. In this way, only the values that should be overridden needs to be supplied.
   * 
   * @param parentPolicy
   *          the name of the parent policy
   */
  @Setter
  private String parentPolicy;

  /**
   * The default ID of the entity that requests a signature. If SAML is used as the authentication protocol, this is the
   * SAML entityID of the sign requester.
   * 
   * @param defaultSignRequesterID
   *          the default sign requester ID
   */
  @Getter
  @Setter
  private String defaultSignRequesterID;

  /**
   * The default URL to which the user agent along with the sign response message should be directed after a signature
   * operation.
   * 
   * @param defaultReturnUrl
   *          the default URL to which a sign response is to be returned
   */
  @Getter
  @Setter
  private String defaultReturnUrl;

  /**
   * The default algorithm identifier for the signature algorithm that should be used during signing of specified tasks.
   * 
   * @param defaultSignatureAlgorithm
   *          signature algorithm identifier
   */
  @Getter
  @Setter
  private String defaultSignatureAlgorithm;

  /**
   * The entityID of the signature service. If SAML is used as the authentication protocol, this is the SAML entityID of
   * the SAML Service Provider that is running in the signature service.
   * 
   * @param signServiceID
   *          the ID of the signature service
   */
  @Getter
  @Setter
  private String signServiceID;

  /**
   * The default signature service URL to where SignRequest messages should be posted.
   * 
   * @param defaultDestinationUrl
   *          the default destination URL of the signature service to where sign messages should be posted
   */
  @Getter
  @Setter
  private String defaultDestinationUrl;

  /**
   * In a setup where only one authentication service (IdP) is used to authenticate users, a default value could be
   * used. If the {@link AuthnRequirements#getAuthnServiceID()} method returns {@code null}, the default value will the
   * be used.
   * 
   * @param defaultAuthnServiceID
   *          the entityID for the default authentication service
   */
  @Getter
  @Setter
  private String defaultAuthnServiceID;

  /**
   * In a setup where all users are authenticated according to the same authentication contect, a default value could be
   * used. If the {@link AuthnRequirements#getAuthnContextRef()} method returns {@code null}, the default value will be
   * used.
   * 
   * @param defaultAuthnContextRef
   *          the default authentication context reference URI
   */
  @Getter
  @Setter
  private String defaultAuthnContextRef;

  /**
   * The default signing certificate requirements to use for SignRequest messages created under this
   * policy/configuration.
   * 
   * @param defaultCertificateRequirements
   *          the default signing certificate requirements
   */
  @Getter
  @Setter
  private SigningCertificateRequirements defaultCertificateRequirements;

  /**
   * A policy may be configured to include a default "visible PDF signature requirement" for all PDF documents that are
   * signed under this policy.
   * 
   * @param defaultVisiblePdfSignatureRequirement
   *          the default visible PDF signature requirement to use for PDF signatures
   */
  @Getter
  @Setter
  private VisiblePdfSignatureRequirement defaultVisiblePdfSignatureRequirement;

  /**
   * A policy may have one, or more, image templates for visible PDF signatures in its configuration. See
   * {@link PdfSignatureImageTemplate}. This method gets these templates.
   * 
   * @param pdfSignatureImageTemplates
   *          a list of image templates for visible PDF signatures
   */
  @Setter
  @Getter
  @Singular
  private List<PdfSignatureImageTemplate> pdfSignatureImageTemplates;

  /**
   * Tells whether the SignService Integration Service is running in stateless mode or not.
   * 
   * @param stateless
   *          stateless mode
   */
  @Setter
  private Boolean stateless;

  /**
   * The default encryption parameters (algorithms) that is used by the SignService Integration Service when encrypting
   * a SignMessage. The sign requester can not override these values, but the recipient may declare other algorithms to
   * use (in the SAML case, this is done in IdP metadata).
   * 
   * @param defaultEncryptionParameters
   *          the default encryption parameters
   */
  @Getter
  @Setter
  private EncryptionParameters defaultEncryptionParameters;

  /**
   * The signing certificate that the SignService Integration Service uses to sign SignRequest messages.
   */
  @Getter
  private String signatureCertificate;

  /**
   * The signing credential that the SignService Integration Service policy instance uses to sign SignRequest messages.
   */
  @JsonIgnore
  @Getter
  private SigningCredential signingCredential;

  /**
   * The signature service signing certificate(s) used by the signature service to sign {@code SignResponse} messages.
   * 
   * @param signServiceCertificates
   *          the signature service signing certificate(s)
   */
  @JsonIgnore
  @Setter
  @Singular
  private List<X509Certificate> signServiceCertificates;

  /**
   * The trust anchor certificate(s) of the SignService CA (Certificate Authority). With trust anchor we mean the
   * trusted root certificate that is the root of the certificate chain that starts with the generated user signature
   * certificate.
   * 
   * @param trustAnchors
   *          the SignService CA root certificates
   */
  @JsonIgnore
  @Setter
  @Singular
  private List<X509Certificate> trustAnchors;

  /**
   * The extension parameters for the instance.
   * 
   * @param extension
   *          the extension
   */
  @Getter
  @Setter
  private Extension extension;

  /**
   * Copy constructor.
   * 
   * @param config
   *          the config object to initialize this object from
   */
  public DefaultIntegrationServiceConfiguration(final IntegrationServiceConfiguration config) {
    this.parentPolicy = config.getPolicy();
    this.mergeConfiguration(config);
  }

  /** {@inheritDoc} */
  @Override
  public String getParentPolicy() {
    return this.parentPolicy;
  }

  /** {@inheritDoc} */
  @Override
  public boolean isStateless() {
    return this.stateless != null ? this.stateless.booleanValue() : false;
  }

  /**
   * Assigns the signing credential that the SignService Integration Service policy instance uses to sign SignRequest
   * messages.
   * 
   * @param signingCredential
   *          the signing credential for the SignService Integration Service policy
   */
  public void setSigningCredential(final SigningCredential signingCredential) {
    this.signingCredential = signingCredential;
    if (this.signingCredential != null && this.signingCredential.getSigningCertificate() != null) {
      try {
        this.signatureCertificate = Base64.getEncoder().encodeToString(this.signingCredential.getSigningCertificate().getEncoded());
      }
      catch (CertificateEncodingException e) {
        log.error("Failed to encode signing certificate", e);
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  public List<X509Certificate> getSignServiceCertificatesInternal() {
    return this.signServiceCertificates != null ? this.signServiceCertificates : Collections.emptyList();
  }

  /** {@inheritDoc} */
  @Override
  @JsonGetter
  public List<String> getSignServiceCertificates() {
    if (this.signServiceCertificates == null) {
      return Collections.emptyList();
    }
    List<String> list = new ArrayList<>();
    for (X509Certificate c : this.signServiceCertificates) {
      try {
        list.add(Base64.getEncoder().encodeToString(c.getEncoded()));
      }
      catch (CertificateEncodingException e) {
        log.error("Failed to encode signature service signing certificate", e);
      }
    }
    return list;
  }

  /** {@inheritDoc} */
  @Override
  public List<X509Certificate> getTrustAnchorsInternal() {
    return this.trustAnchors != null ? this.trustAnchors : Collections.emptyList();
  }

  /** {@inheritDoc} */
  @Override
  @JsonGetter
  public List<String> getTrustAnchors() {
    if (this.trustAnchors == null) {
      return Collections.emptyList();
    }
    List<String> list = new ArrayList<>();
    for (X509Certificate c : this.trustAnchors) {
      try {
        list.add(Base64.getEncoder().encodeToString(c.getEncoded()));
      }
      catch (CertificateEncodingException e) {
        log.error("Failed to encode signature service CA trust anchor", e);
      }
    }
    return list;
  }

  /** {@inheritDoc} */
  @Override
  @JsonIgnore
  public IntegrationServiceDefaultConfiguration getPublicConfiguration() {
    DefaultIntegrationServiceConfigurationBuilder builder = this.toBuilder();
    builder.signingCredential(null);
    builder.parentPolicy(null);
    return builder.build();
  }

  /** {@inheritDoc} */
  @Override
  public void mergeConfiguration(final IntegrationServiceConfiguration parent) {

    if (!parent.getPolicy().equals(this.parentPolicy)) {
      throw new IllegalArgumentException("Invalid policy merge");
    }

    if (!StringUtils.hasText(this.defaultSignRequesterID)) {
      this.defaultSignRequesterID = parent.getDefaultSignRequesterID();
    }
    if (!StringUtils.hasText(this.defaultReturnUrl)) {
      this.defaultReturnUrl = parent.getDefaultReturnUrl();
    }
    if (!StringUtils.hasText(this.defaultSignatureAlgorithm)) {
      this.defaultSignatureAlgorithm = parent.getDefaultSignatureAlgorithm();
    }
    if (!StringUtils.hasText(this.signServiceID)) {
      this.signServiceID = parent.getSignServiceID();
    }
    if (!StringUtils.hasText(this.defaultDestinationUrl)) {
      this.defaultDestinationUrl = parent.getDefaultDestinationUrl();
    }
    if (!StringUtils.hasText(this.defaultAuthnServiceID)) {
      this.defaultAuthnServiceID = parent.getDefaultAuthnServiceID();
    }
    if (!StringUtils.hasText(this.defaultAuthnContextRef)) {
      this.defaultAuthnContextRef = parent.getDefaultAuthnContextRef();
    }
    if (this.defaultCertificateRequirements == null) {
      this.defaultCertificateRequirements = parent.getDefaultCertificateRequirements();
    }
    if (this.defaultVisiblePdfSignatureRequirement == null) {
      this.defaultVisiblePdfSignatureRequirement = parent.getDefaultVisiblePdfSignatureRequirement();
    }
    if (this.pdfSignatureImageTemplates == null || this.pdfSignatureImageTemplates.isEmpty()) {
      this.pdfSignatureImageTemplates = parent.getPdfSignatureImageTemplates();
    }
    if (this.stateless == null) {
      this.stateless = parent.isStateless();
    }
    if (this.defaultEncryptionParameters == null) {
      this.defaultEncryptionParameters = parent.getDefaultEncryptionParameters();
    }
    if (this.signingCredential == null) {
      this.signingCredential = parent.getSigningCredential();
    }
    if (this.signServiceCertificates == null) {
      this.signServiceCertificates = parent.getSignServiceCertificatesInternal();
    }
    if (this.trustAnchors == null) {
      this.trustAnchors = parent.getTrustAnchorsInternal();
    }
    if (this.extension == null) {
      this.extension = parent.getExtension();
    }
    else {
      parent.getExtension().entrySet().stream().forEach(e -> this.extension.put(e.getKey(), e.getValue()));
    }

    // OK, merge is done. We no longer have a parent.
    this.parentPolicy = null;
  }

  /**
   * Builder for {@code DefaultIntegrationServiceConfiguration} objects.
   */
  public static class DefaultIntegrationServiceConfigurationBuilder implements ObjectBuilder<DefaultIntegrationServiceConfiguration> {
    // Lombok

    public DefaultIntegrationServiceConfigurationBuilder signingCredential(final SigningCredential signingCredential) {
      this.signingCredential = signingCredential;
      if (this.signingCredential != null && this.signingCredential.getSigningCertificate() != null) {
        try {
          this.signatureCertificate = Base64.getEncoder().encodeToString(this.signingCredential.getSigningCertificate().getEncoded());
        }
        catch (CertificateEncodingException e) {
          log.error("Failed to encode signing certificate", e);
        }
      }
      return this;
    }
  }

}
