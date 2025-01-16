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

import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.Singular;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import se.idsec.signservice.integration.ExtendedSignServiceIntegrationService;
import se.idsec.signservice.integration.authentication.AuthnRequirements;
import se.idsec.signservice.integration.certificate.SigningCertificateRequirements;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.config.IntegrationServiceDefaultConfiguration;
import se.idsec.signservice.integration.core.Extension;
import se.idsec.signservice.integration.core.ObjectBuilder;
import se.idsec.signservice.integration.document.pdf.PdfPrepareSettings;
import se.idsec.signservice.integration.document.pdf.PdfSignatureImageTemplate;
import se.idsec.signservice.integration.document.pdf.PdfSignaturePage;
import se.idsec.signservice.integration.document.pdf.PdfSignaturePagePreferences;
import se.idsec.signservice.integration.document.pdf.VisiblePdfSignatureRequirement;
import se.idsec.signservice.integration.security.EncryptionParameters;
import se.swedenconnect.security.credential.PkiCredential;

import java.io.Serial;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

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

  @Serial
  private static final long serialVersionUID = -114861382087789967L;

  /**
   * The integration policy name for which this configuration applies.
   */
  @Setter
  private String policy;

  /**
   * If several policies are created where most settings are the same, the {@code parentPolicy} can be used to inherit
   * values from. In this way, only the values that should be overridden needs to be supplied.
   */
  @Setter
  private String parentPolicy;

  /**
   * The default ID of the entity that requests a signature. If SAML is used as the authentication protocol, this is the
   * SAML entityID of the sign requester.
   */
  @Setter
  private String defaultSignRequesterID;

  /**
   * The default URL to which the user agent along with the sign response message should be directed after a signature
   * operation.
   */
  @Setter
  private String defaultReturnUrl;

  /**
   * The default algorithm identifier for the signature algorithm that should be used during signing of specified
   * tasks.
   */
  @Setter
  private String defaultSignatureAlgorithm;

  /**
   * The entityID of the signature service. If SAML is used as the authentication protocol, this is the SAML entityID of
   * the SAML Service Provider that is running in the signature service.
   */
  @Setter
  private String signServiceID;

  /**
   * The default signature service URL to where SignRequest messages should be posted.
   */
  @Setter
  private String defaultDestinationUrl;

  /**
   * In a setup where only one authentication service (IdP) is used to authenticate users, a default value could be
   * used. If the {@link AuthnRequirements#getAuthnServiceID()} method returns {@code null}, the default value will be
   * used.
   */
  @Setter
  private String defaultAuthnServiceID;

  /**
   * In a setup where all users are authenticated according to the same authentication contect, a default value could be
   * used. If the {@link AuthnRequirements#getAuthnContextClassRefs()} method returns {@code null} or an empty list, the
   * default value will be used.
   */
  @Setter
  private String defaultAuthnContextRef;

  /**
   * The default signing certificate requirements to use for SignRequest messages created under this
   * policy/configuration.
   */
  @Setter
  private SigningCertificateRequirements defaultCertificateRequirements;

  /**
   * A policy may be configured to include a default "visible PDF signature requirement" for all PDF documents that are
   * signed under this policy.
   */
  @Setter
  private VisiblePdfSignatureRequirement defaultVisiblePdfSignatureRequirement;

  /**
   * A policy may have one, or more, image templates for visible PDF signatures in its configuration. See
   * {@link PdfSignatureImageTemplate}. This method gets these templates.
   */
  @Setter
  @Singular
  private List<? extends PdfSignatureImageTemplate> pdfSignatureImageTemplates;

  /**
   * A policy may have one, or more, configured PDF signature pages. See
   * {@link ExtendedSignServiceIntegrationService#preparePdfDocument(String, byte[], PdfSignaturePagePreferences,
   * Boolean, String)} for a description of PDF signature pages. The first object in the list is regarded as the default
   * page for the policy.
   */
  @Setter
  @Singular
  private List<? extends PdfSignaturePage> pdfSignaturePages;

  /**
   * Tells whether the SignService Integration Service is running in stateless mode or not.
   */
  @Setter
  private Boolean stateless;

  /**
   * The default encryption parameters (algorithms) that is used by the SignService Integration Service when encrypting
   * a SignMessage. The sign requester can not override these values, but the recipient may declare other algorithms to
   * use (in the SAML case, this is done in IdP metadata).
   */
  @Setter
  private EncryptionParameters defaultEncryptionParameters;

  /**
   * The signing certificate that the SignService Integration Service uses to sign SignRequest messages.
   */
  private String signatureCertificate;

  /**
   * The signing credential that the SignService Integration Service policy instance uses to sign SignRequest messages.
   */
  @JsonIgnore
  @Getter
  private PkiCredential signingCredential;

  /**
   * The signature service signing certificate(s) used by the signature service to sign {@code SignResponse} messages.
   */
  @JsonIgnore
  @Setter
  @Singular
  private List<X509Certificate> signServiceCertificates;

  /**
   * The trust anchor certificate(s) of the SignService CA (Certificate Authority). With trust anchor we mean the
   * trusted root certificate that is the root of the certificate chain that starts with the generated user signature
   * certificate.
   */
  @JsonIgnore
  @Setter
  @Singular
  private List<X509Certificate> trustAnchors;

  /**
   * Settings for PDF preparing.
   */
  @Setter
  private PdfPrepareSettings pdfPrepareSettings;

  /**
   * The extension parameters for the instance.
   */
  @Getter
  @Setter
  private Extension extension;

  /**
   * Copy constructor.
   *
   * @param config the config object to initialize this object from
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
    return this.stateless != null ? this.stateless : false;
  }

  /** {@inheritDoc} */
  @Nonnull
  @Override
  public String getPolicy() {
    return this.policy;
  }

  /** {@inheritDoc} */
  @Nullable
  @Override
  public String getDefaultSignRequesterID() {
    return this.defaultSignRequesterID;
  }

  /** {@inheritDoc} */
  @Nullable
  @Override
  public String getDefaultReturnUrl() {
    return this.defaultReturnUrl;
  }

  /** {@inheritDoc} */
  @Nullable
  @Override
  public String getDefaultSignatureAlgorithm() {
    return this.defaultSignatureAlgorithm;
  }

  /** {@inheritDoc} */
  @Nonnull
  @Override
  public String getSignServiceID() {
    return this.signServiceID;
  }

  /** {@inheritDoc} */
  @Nullable
  @Override
  public String getDefaultDestinationUrl() {
    return this.defaultDestinationUrl;
  }

  /** {@inheritDoc} */
  @Nullable
  @Override
  public String getDefaultAuthnServiceID() {
    return this.defaultAuthnServiceID;
  }

  /** {@inheritDoc} */
  @Nullable
  @Override
  public String getDefaultAuthnContextRef() {
    return this.defaultAuthnContextRef;
  }

  /** {@inheritDoc} */
  @Nullable
  @Override
  public SigningCertificateRequirements getDefaultCertificateRequirements() {
    return this.defaultCertificateRequirements;
  }

  /** {@inheritDoc} */
  @Nullable
  @Override
  public VisiblePdfSignatureRequirement getDefaultVisiblePdfSignatureRequirement() {
    return this.defaultVisiblePdfSignatureRequirement;
  }

  /** {@inheritDoc} */
  @Nullable
  @Override
  public List<? extends PdfSignatureImageTemplate> getPdfSignatureImageTemplates() {
    return this.pdfSignatureImageTemplates;
  }

  /** {@inheritDoc} */
  @Nullable
  @Override
  public List<? extends PdfSignaturePage> getPdfSignaturePages() {
    return this.pdfSignaturePages;
  }

  /** {@inheritDoc} */
  @Nullable
  @Override
  public EncryptionParameters getDefaultEncryptionParameters() {
    return this.defaultEncryptionParameters;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String getSignatureCertificate() {
    if (this.signatureCertificate == null) {
      if (this.signingCredential != null && this.signingCredential.getCertificate() != null) {
        try {
          this.signatureCertificate =
              Base64.getEncoder().encodeToString(this.signingCredential.getCertificate().getEncoded());
        }
        catch (final CertificateEncodingException e) {
          log.error("Failed to encode signing certificate", e);
        }
      }
    }
    return this.signatureCertificate;
  }

  /**
   * Assigns the signing credential that the SignService Integration Service policy instance uses to sign SignRequest
   * messages.
   *
   * @param signingCredential the signing credential for the SignService Integration Service policy
   */
  public void setSigningCredential(final PkiCredential signingCredential) {
    this.signingCredential = signingCredential;
    if (this.signingCredential != null && this.signingCredential.getCertificate() != null) {
      try {
        this.signatureCertificate =
            Base64.getEncoder().encodeToString(this.signingCredential.getCertificate().getEncoded());
      }
      catch (final CertificateEncodingException e) {
        log.error("Failed to encode signing certificate", e);
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  @JsonIgnore
  public List<X509Certificate> getSignServiceCertificatesInternal() {
    return this.signServiceCertificates != null ? this.signServiceCertificates : Collections.emptyList();
  }

  /** {@inheritDoc} */
  @Override
  @JsonGetter
  @Nonnull
  public List<String> getSignServiceCertificates() {
    if (this.signServiceCertificates == null) {
      return Collections.emptyList();
    }
    final List<String> list = new ArrayList<>();
    for (final X509Certificate c : this.signServiceCertificates) {
      try {
        list.add(Base64.getEncoder().encodeToString(c.getEncoded()));
      }
      catch (final CertificateEncodingException e) {
        log.error("Failed to encode signature service signing certificate", e);
      }
    }
    return list;
  }

  /** {@inheritDoc} */
  @Override
  @JsonIgnore
  public List<X509Certificate> getTrustAnchorsInternal() {
    return this.trustAnchors != null ? this.trustAnchors : Collections.emptyList();
  }

  /** {@inheritDoc} */
  @Override
  @JsonGetter
  @Nonnull
  public List<String> getTrustAnchors() {
    if (this.trustAnchors == null) {
      return Collections.emptyList();
    }
    final List<String> list = new ArrayList<>();
    for (final X509Certificate c : this.trustAnchors) {
      try {
        list.add(Base64.getEncoder().encodeToString(c.getEncoded()));
      }
      catch (final CertificateEncodingException e) {
        log.error("Failed to encode signature service CA trust anchor", e);
      }
    }
    return list;
  }

  /** {@inheritDoc} */
  @Nonnull
  @Override
  public PdfPrepareSettings getPdfPrepareSettings() {
    return Optional.ofNullable(this.pdfPrepareSettings).orElse(PdfPrepareSettings.DEFAULT);
  }

  /** {@inheritDoc} */
  @Override
  @JsonIgnore
  public IntegrationServiceDefaultConfiguration getPublicConfiguration() {
    final DefaultIntegrationServiceConfigurationBuilder builder = this.toBuilder();
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

    if (StringUtils.isBlank(this.defaultSignRequesterID)) {
      this.defaultSignRequesterID = parent.getDefaultSignRequesterID();
    }
    if (StringUtils.isBlank(this.defaultReturnUrl)) {
      this.defaultReturnUrl = parent.getDefaultReturnUrl();
    }
    if (StringUtils.isBlank(this.defaultSignatureAlgorithm)) {
      this.defaultSignatureAlgorithm = parent.getDefaultSignatureAlgorithm();
    }
    if (StringUtils.isBlank(this.signServiceID)) {
      this.signServiceID = parent.getSignServiceID();
    }
    if (StringUtils.isBlank(this.defaultDestinationUrl)) {
      this.defaultDestinationUrl = parent.getDefaultDestinationUrl();
    }
    if (StringUtils.isBlank(this.defaultAuthnServiceID)) {
      this.defaultAuthnServiceID = parent.getDefaultAuthnServiceID();
    }
    if (StringUtils.isBlank(this.defaultAuthnContextRef)) {
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
    if (this.pdfSignaturePages == null || this.pdfSignaturePages.isEmpty()) {
      this.pdfSignaturePages = parent.getPdfSignaturePages();
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
    if (this.signServiceCertificates == null || this.signServiceCertificates.isEmpty()) {
      this.signServiceCertificates = parent.getSignServiceCertificatesInternal();
    }
    if (this.trustAnchors == null || this.trustAnchors.isEmpty()) {
      this.trustAnchors = parent.getTrustAnchorsInternal();
    }
    if (this.pdfPrepareSettings == null) {
      this.pdfPrepareSettings = parent.getPdfPrepareSettings();
    }
    if (this.extension == null) {
      this.extension = parent.getExtension();
    }
    else {
      parent.getExtension().forEach((key, value) -> this.extension.putIfAbsent(key, value));
    }

    // OK, merge is done. We no longer have a parent.
    this.parentPolicy = null;
  }

  /**
   * Builder for {@code DefaultIntegrationServiceConfiguration} objects.
   */
  public static class DefaultIntegrationServiceConfigurationBuilder
      implements ObjectBuilder<DefaultIntegrationServiceConfiguration> {
    // Lombok

    public DefaultIntegrationServiceConfigurationBuilder signingCredential(final PkiCredential signingCredential) {
      this.signingCredential = signingCredential;
      if (this.signingCredential != null && this.signingCredential.getCertificate() != null) {
        try {
          this.signatureCertificate =
              Base64.getEncoder().encodeToString(this.signingCredential.getCertificate().getEncoded());
        }
        catch (final CertificateEncodingException e) {
          log.error("Failed to encode signing certificate", e);
        }
      }
      return this;
    }
  }

}
