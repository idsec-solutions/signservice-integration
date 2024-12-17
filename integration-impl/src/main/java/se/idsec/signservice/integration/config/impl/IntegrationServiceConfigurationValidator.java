/*
 * Copyright 2019-2023 IDsec Solutions AB
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

import jakarta.annotation.Nullable;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import se.idsec.signservice.integration.certificate.impl.SigningCertificateRequirementsValidator;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.validation.AbstractInputValidator;
import se.idsec.signservice.integration.core.validation.ValidationResult;
import se.idsec.signservice.integration.document.impl.PdfSignaturePageValidator;
import se.idsec.signservice.integration.document.impl.VisiblePdfSignatureRequirementValidator;
import se.idsec.signservice.integration.document.pdf.PdfSignatureImageTemplate;
import se.idsec.signservice.integration.document.pdf.PdfSignaturePage;
import se.idsec.signservice.integration.security.EncryptionParameters;

import java.lang.reflect.Constructor;

/**
 * Validator for {@link IntegrationServiceConfiguration} objects.
 * <p>
 * Note: This implementation is package-private and is used internally by {@link DefaultConfigurationManager}.
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
class IntegrationServiceConfigurationValidator extends
    AbstractInputValidator<IntegrationServiceConfiguration, Void> {

  /** Validator for EncryptionParameters. */
  private final EncryptionParametersValidator encryptionParametersValidator = new EncryptionParametersValidator();

  /** Validator for SigningCertificateRequirements. */
  private final SigningCertificateRequirementsValidator defaultCertificateRequirementsValidator =
      new SigningCertificateRequirementsValidator();

  /** Validator for VisiblePdfSignatureRequirement. */
  private final VisiblePdfSignatureRequirementValidator defaultVisiblePdfSignatureRequirementValidator =
      new VisiblePdfSignatureRequirementValidator();

  /** Validator for FileResource objects. */
  private final FileResourceValidator fileResourceValidator = new FileResourceValidator();

  /** Validator for PdfSignaturePage objects. */
  private PdfSignaturePageValidator pdfSignaturePageValidator;

  /**
   * Constructor.
   */
  public IntegrationServiceConfigurationValidator() {
    try {
      // If we have the pdf jar in the classpath we want to use the extended PDF validator that also
      // loads the PDF signature page and ensures that it is a valid PDF document ...
      //
      final Class<?> clazz = Class.forName(
          "se.idsec.signservice.integration.document.pdf.signpage.impl.ExtendedPdfSignaturePageValidator");
      final Constructor<?> ctor = clazz.getConstructor();
      this.pdfSignaturePageValidator = (PdfSignaturePageValidator) ctor.newInstance();
    }
    catch (final Exception e) {
      // We don't have the extended validator in the classpath, so we'll use the standard one that does
      // now have support for loaded PDF documents.
      this.pdfSignaturePageValidator = new PdfSignaturePageValidator();
    }
  }

  /** {@inheritDoc} */
  @Override
  public ValidationResult validate(final IntegrationServiceConfiguration object, @Nullable final String objectName,
      final Void hint) {
    if (object == null) {
      throw new IllegalArgumentException("IntegrationServiceConfiguration object must not be null");
    }
    final ValidationResult result = new ValidationResult(objectName);

    // Policy
    if (StringUtils.isBlank(object.getPolicy())) {
      result.rejectValue("policy", "Missing policy name");
    }

    // DefaultSignRequesterID
    if (StringUtils.isBlank(object.getDefaultSignRequesterID())) {
      log.warn("Service configuration '{}' does not specify a defaultSignRequesterID value", object.getPolicy());
    }

    // DefaultReturnUrl
    if (StringUtils.isBlank(object.getDefaultReturnUrl())) {
      log.warn("Service configuration '{}' does not specify a defaultReturnUrl value", object.getPolicy());
    }

    // DefaultSignatureAlgorithm
    if (StringUtils.isBlank(object.getDefaultDestinationUrl())) {
      result.rejectValue("defaultSignatureAlgorithm", "Missing defaultSignatureAlgorithm");
    }

    // SignServiceID
    if (StringUtils.isBlank(object.getSignServiceID())) {
      result.rejectValue("signServiceID", "Missing signServiceID");
    }

    // DefaultDestinationUrl
    if (StringUtils.isBlank(object.getDefaultDestinationUrl())) {
      result.rejectValue("defaultDestinationUrl", "Missing defaultDestinationUrl");
    }

    // DefaultCertificateRequirements
    if (object.getDefaultCertificateRequirements() == null) {
      result.rejectValue("defaultCertificateRequirements", "Missing defaultCertificateRequirements");
    }
    else if (object.getDefaultCertificateRequirements().getCertificateType() == null) {
      result.rejectValue("defaultCertificateRequirements.certificateType",
          "Missing certificateType in defaultCertificateRequirements");
    }
    else if (object.getDefaultCertificateRequirements().getAttributeMappings() == null
        || object.getDefaultCertificateRequirements().getAttributeMappings().isEmpty()) {
      result.rejectValue("defaultCertificateRequirements.attributeMappings",
          "Missing attributeMappings in defaultCertificateRequirements");
    }
    else {
      result.setFieldErrors(this.defaultCertificateRequirementsValidator.validate(
          object.getDefaultCertificateRequirements(), "defaultCertificateRequirements", null));
    }

    // PdfSignatureImageTemplates
    if (object.getPdfSignatureImageTemplates() != null && !object.getPdfSignatureImageTemplates().isEmpty()) {
      int pos = 0;
      for (final PdfSignatureImageTemplate pdfTemplate : object.getPdfSignatureImageTemplates()) {
        if (pdfTemplate.getReference() == null) {
          result.rejectValue("pdfSignatureImageTemplates[" + pos + "].reference",
              "Missing reference ID for PdfSignatureImageTemplate");
        }
        if (pdfTemplate.getSvgImageFile() == null) {
          result.rejectValue("pdfSignatureImageTemplates[" + pos + "].svgImageFile",
              "Missing svgImageFile for PdfSignatureImageTemplate");
        }
        else {
          result.setFieldErrors(
              this.fileResourceValidator.validate(pdfTemplate.getSvgImageFile(),
                  "pdfSignatureImageTemplates[" + pos + "].svgImageFile",
                  null));
        }
        if (pdfTemplate.getHeight() == null) {
          result.rejectValue("pdfSignatureImageTemplates[" + pos + "].height",
              "Missing height property for PdfSignatureImageTemplate");
        }
        else if (pdfTemplate.getHeight() < 0) {
          result.rejectValue("pdfSignatureImageTemplates[" + pos + "].height",
              "Illegal value for height property for PdfSignatureImageTemplate");
        }
        if (pdfTemplate.getWidth() == null) {
          result.rejectValue("pdfSignatureImageTemplates[" + pos + "].width",
              "Missing width property for PdfSignatureImageTemplate");
        }
        else if (pdfTemplate.getWidth() < 0) {
          result.rejectValue("pdfSignatureImageTemplates[" + pos + "].width",
              "Illegal value for width property for PdfSignatureImageTemplate");
        }
        pos++;
      }
    }

    // DefaultVisiblePdfSignatureRequirement
    // Also checks the field values for PdfSignatureImageTemplates
    if (object.getDefaultVisiblePdfSignatureRequirement() != null) {
      result.setFieldErrors(this.defaultVisiblePdfSignatureRequirementValidator.validate(
          object.getDefaultVisiblePdfSignatureRequirement(), "defaultVisiblePdfSignatureRequirement", object));
    }

    // PdfSignaturePages
    if (object.getPdfSignaturePages() != null && !object.getPdfSignaturePages().isEmpty()) {
      final int pos = 0;
      for (final PdfSignaturePage page : object.getPdfSignaturePages()) {
        result.setFieldErrors(this.pdfSignaturePageValidator.validate(
            page, "pdfSignaturePages[" + pos + "]", object.getPdfSignatureImageTemplates()));
      }
    }

    // DefaultEncryptionParameters
    if (object.getDefaultEncryptionParameters() == null) {
      result.rejectValue("defaultEncryptionParameters", "Missing defaultEncryptionParameters");
    }
    else {
      result.setFieldErrors(this.encryptionParametersValidator.validate(
          object.getDefaultEncryptionParameters(), "defaultEncryptionParameters", null));
    }

    // SignatureCertificate
    if (object.getSignatureCertificate() == null) {
      result.rejectValue("signatureCertificate", "Missing signatureCertificate");
    }

    // SignServiceCertificates
    if (object.getSignServiceCertificates() == null || object.getSignServiceCertificates().isEmpty()) {
      result.rejectValue("signServiceCertificates", "The signServiceCertificates list must be non-empty");
    }

    // SigningCredential
    if (object.getSigningCredential() == null) {
      result.rejectValue("signingCredential", "Missing signingCredential");
    }
    else if (object.getSigningCredential().getPrivateKey() == null) {
      result.rejectValue("signingCredential.privateKey", "No private key available in signingCredential");
    }
    else if (object.getSigningCredential().getCertificate() == null) {
      result.rejectValue("signingCredential.signingCertificate",
          "No signing certificate available in signingCredential");
    }

    return result;
  }

  /**
   * Validator for {@link EncryptionParameters}.
   *
   * @author Martin Lindström (martin@idsec.se)
   * @author Stefan Santesson (stefan@idsec.se)
   */
  private static class EncryptionParametersValidator extends AbstractInputValidator<EncryptionParameters, Void> {

    /** {@inheritDoc} */
    @Override
    public ValidationResult validate(final EncryptionParameters object, @Nullable final String objectName,
        final Void hint) {
      final ValidationResult result = new ValidationResult(objectName);

      if (StringUtils.isBlank(object.getDataEncryptionAlgorithm())) {
        result.rejectValue("dataEncryptionAlgorithm", "getDataEncryptionAlgorithm is not set");
      }
      if (StringUtils.isBlank(object.getKeyTransportEncryptionAlgorithm())) {
        result.rejectValue("keyTransportEncryptionAlgorithm", "keyTransportEncryptionAlgorithm is not set");
      }
      return result;
    }
  }

}
