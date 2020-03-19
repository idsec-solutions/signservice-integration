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
package se.idsec.signservice.integration.document.pdf;

import java.util.List;

import org.springframework.util.StringUtils;

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

  /** {@inheritDoc} */
  @Override
  public ValidationResult validate(final VisiblePdfSignatureRequirement object, final String objectName,
      final IntegrationServiceConfiguration hint) {

    final ValidationResult result = new ValidationResult(objectName);
    if (object == null) {
      return result;
    }
    final List<PdfSignatureImageTemplate> templates = hint.getPdfSignatureImageTemplates();

    final PdfSignatureImageTemplate template = object.getTemplateImageRef() != null
        ? templates.stream()
          .filter(t -> object.getTemplateImageRef().equals(t.getReference()))
          .findFirst()
          .orElse(null)
        : null;

    if (!StringUtils.hasText(object.getTemplateImageRef())) {
      result.rejectValue("templateImageRef", "PDF template reference is required");
    }
    else if (template == null) {
      result.rejectValue("templateImageRef",
        String.format("The PDF template reference '%s' could not be found in the configuration", object.getTemplateImageRef()));
    }
    if (object.getXPosition() == null) {
      result.rejectValue("xPosition", "Missing xPosition value");
    }
    if (object.getXPosition().intValue() < 0) {
      result.rejectValue("xPosition", "Illegal value for xPosition given in visiblePdfSignatureRequirement");
    }
    if (object.getYPosition() == null) {
      result.rejectValue("yPosition", "Missing yPosition value");
    }
    if (object.getYPosition().intValue() < 0) {
      result.rejectValue("yPosition", "Illegal value for yPosition given in visiblePdfSignatureRequirement");
    }

    // Check signerName ...
    //
    if (template != null && template.isIncludeSignerName()) {
      if (object.getSignerName() == null || object.getSignerName().getSignerAttributes() == null
          || object.getSignerName().getSignerAttributes().isEmpty()) {
        result.rejectValue("signerName", String.format(
          "Requested templateImageRef '%s' requires signerName, but requirements does not include visiblePdfSignatureRequirement.signerName",
          object.getTemplateImageRef()));
      }
    }
    // Make sure that all fields required by the template are given in the requirement.
    //
    if (template != null && template.getFields() != null) {
      for (final String field : template.getFields().keySet()) {
        if (PdfSignatureImageTemplate.SIGNER_NAME_FIELD_NAME.equals(field)
            || PdfSignatureImageTemplate.SIGNING_TIME_FIELD_NAME.equals(field)) {
          continue;
        }
        if (object.getFieldValues() == null) {
          result.rejectValue("fieldValues", String.format(
            "The field {0} is required by template, but not given in input", field));
        }
        else if (object.getFieldValues().get(field) == null) {
          result.rejectValue("fieldValues", String.format(
            "The field {0} is required by template, but not given in input", field));
        }
      }
    }

    return result;
  }

}
