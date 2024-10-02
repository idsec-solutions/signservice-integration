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

import jakarta.annotation.Nullable;
import se.idsec.signservice.integration.core.validation.AbstractInputValidator;
import se.idsec.signservice.integration.core.validation.ValidationResult;
import se.idsec.signservice.integration.document.pdf.PdfSignatureImageTemplate;
import se.idsec.signservice.integration.document.pdf.VisiblePdfSignatureUserInformation;

/**
 * Validator for {@link VisiblePdfSignatureUserInformation} objects.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class VisiblePdfSignatureUserInformationValidator
    extends AbstractInputValidator<VisiblePdfSignatureUserInformation, PdfSignatureImageTemplate> {

  /** {@inheritDoc} */
  @Override
  public ValidationResult validate(
      final VisiblePdfSignatureUserInformation object, @Nullable final String objectName,
      final PdfSignatureImageTemplate hint) {

    final ValidationResult result = new ValidationResult(objectName);
    if (object == null) {
      return result;
    }

    if (hint == null) {
      result.reject("No PdfSignatureImageTemplate found for visiblePdfSignatureUserInformation");
      return result;
    }

    // Check signerName ...
    //
    if (hint.isIncludeSignerName()) {
      if (object.getSignerName() == null || object.getSignerName().getSignerAttributes() == null
          || object.getSignerName().getSignerAttributes().isEmpty()) {
        result.rejectValue("signerName", String.format(
            "Requested templateImageRef '%s' requires signerName, but requirements does not include visiblePdfSignatureRequirement.signerName",
            hint.getReference()));
      }
    }
    // Make sure that all fields required by the template are given in the requirement.
    //
    if (hint.getFields() != null) {
      for (final String field : hint.getFields().keySet()) {
        if (PdfSignatureImageTemplate.SIGNER_NAME_FIELD_NAME.equalsIgnoreCase(field)
            || PdfSignatureImageTemplate.SIGNING_TIME_FIELD_NAME.equalsIgnoreCase(field)) {
          continue;
        }
        if (object.getFieldValues() == null) {
          result.rejectValue("fieldValues." + field, String.format(
              "The field %s is required by template, but not given in input", field));
        }
        else if (object.getFieldValues().keySet().stream().noneMatch(f -> field.equalsIgnoreCase(f))) {
          result.rejectValue("fieldValues." + field, String.format(
              "The field %s is required by template, but not given in input", field));
        }
      }
    }

    return result;
  }

}
