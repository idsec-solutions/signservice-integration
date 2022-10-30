/*
 * Copyright 2019-2022 IDsec Solutions AB
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
package se.idsec.signservice.integration.document.impl;

import java.util.List;

import org.apache.commons.lang.StringUtils;

import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.validation.AbstractInputValidator;
import se.idsec.signservice.integration.core.validation.ValidationResult;
import se.idsec.signservice.integration.document.pdf.PdfSignatureImageTemplate;
import se.idsec.signservice.integration.document.pdf.VisiblePdfSignatureRequirement;

/**
 * Validator for {@link VisiblePdfSignatureRequirement} objects.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class VisiblePdfSignatureRequirementValidator extends
    AbstractInputValidator<VisiblePdfSignatureRequirement, IntegrationServiceConfiguration> {

  /** Validator for VisiblePdfSignatureUserInformation objects. */
  private VisiblePdfSignatureUserInformationValidator visiblePdfSignatureUserInformationValidator =
      new VisiblePdfSignatureUserInformationValidator();

  /** {@inheritDoc} */
  @Override
  public ValidationResult validate(final VisiblePdfSignatureRequirement object, final String objectName,
      final IntegrationServiceConfiguration hint) {

    final ValidationResult result = new ValidationResult(objectName);
    if (object == null) {
      return result;
    }
    final List<? extends PdfSignatureImageTemplate> templates = hint.getPdfSignatureImageTemplates();

    final PdfSignatureImageTemplate template = object.getTemplateImageRef() != null
        ? templates != null
            ? templates.stream()
              .filter(t -> object.getTemplateImageRef().equals(t.getReference()))
              .findFirst()
              .orElse(null)
            : null
        : null;

    if (StringUtils.isBlank(object.getTemplateImageRef())) {
      result.rejectValue("templateImageRef", "PDF template reference is required");
    }
    else if (template == null) {
      result.rejectValue("templateImageRef",
        String.format("The PDF template reference '%s' could not be found in the configuration", object.getTemplateImageRef()));
    }
    if (object.getXPosition() == null) {
      result.rejectValue("xPosition", "Missing xPosition value");
    }
    else if (object.getXPosition().intValue() < 0) {
      result.rejectValue("xPosition", "Illegal value for xPosition given in visiblePdfSignatureRequirement");
    }
    if (object.getYPosition() == null) {
      result.rejectValue("yPosition", "Missing yPosition value");
    }
    else if (object.getYPosition().intValue() < 0) {
      result.rejectValue("yPosition", "Illegal value for yPosition given in visiblePdfSignatureRequirement");
    }

    result.setFieldErrors(
      this.visiblePdfSignatureUserInformationValidator.validate(object, null, template));

    return result;
  }

}
