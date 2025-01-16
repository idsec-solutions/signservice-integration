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
package se.idsec.signservice.integration.document.impl;

import jakarta.annotation.Nullable;
import se.idsec.signservice.integration.config.impl.FileResourceValidator;
import se.idsec.signservice.integration.core.validation.AbstractInputValidator;
import se.idsec.signservice.integration.core.validation.ValidationResult;
import se.idsec.signservice.integration.document.pdf.PdfSignatureImageTemplate;
import se.idsec.signservice.integration.document.pdf.PdfSignaturePage;
import se.idsec.signservice.integration.document.pdf.PdfSignaturePage.PdfSignatureImagePlacementConfiguration;

import java.util.List;

/**
 * Validator for {@link PdfSignaturePage} objects.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class PdfSignaturePageValidator
    extends AbstractInputValidator<PdfSignaturePage, List<? extends PdfSignatureImageTemplate>> {

  /** Validator for FileResource objects. */
  private final FileResourceValidator fileResourceValidator = new FileResourceValidator();

  /** {@inheritDoc} */
  @Override
  public ValidationResult validate(final PdfSignaturePage object, @Nullable final String objectName,
      final List<? extends PdfSignatureImageTemplate> hint) {
    final ValidationResult result = new ValidationResult(objectName);
    if (object == null) {
      return result;
    }
    if (object.getId() == null) {
      result.rejectValue("id", "Missing id for PdfSignaturePage");
    }
    if (object.getPdfDocument() == null) {
      result.rejectValue("pdfDocument", "Missing pdfDocument for PdfSignaturePage");
    }
    else {
      result.setFieldErrors(
          this.fileResourceValidator.validate(object.getPdfDocument(), "pdfDocument", null));
    }
    if (object.getSignatureImageReference() == null) {
      result.rejectValue("signatureImageReference", "Missing signatureImageReference for PdfSignaturePage");
    }
    else {
      // Assert that the signature image reference points to a valid PdfSignatureImageTemplate ...
      PdfSignatureImageTemplate template = null;
      if (hint != null) {
        template = hint.stream()
            .filter(t -> object.getSignatureImageReference().equals(t.getReference()))
            .findFirst()
            .orElse(null);
      }
      if (template == null) {
        result.rejectValue("signatureImageReference", "No PdfSignatureImageTemplate matching signatureImageReference");
      }
    }
    if (object.getImagePlacementConfiguration() == null) {
      result.rejectValue("imagePlacementConfiguration", "Missing imagePlacementConfiguration for PdfSignaturePage");
    }
    else {
      final PdfSignatureImagePlacementConfiguration config = object.getImagePlacementConfiguration();
      if (config.getXPosition() == null) {
        result.rejectValue("imagePlacementConfiguration.xPosition",
            "Missing xPosition of imagePlacementConfiguration for PdfSignaturePage");
      }
      else if (config.getXPosition() < 0) {
        result.rejectValue("imagePlacementConfiguration.xPosition",
            "Invalid value for xPosition of imagePlacementConfiguration for PdfSignaturePage");
      }
      if (config.getYPosition() == null) {
        result.rejectValue("imagePlacementConfiguration.yPosition",
            "Missing yPosition of imagePlacementConfiguration for PdfSignaturePage");
      }
      else if (config.getYPosition() < 0) {
        result.rejectValue("imagePlacementConfiguration.yPosition",
            "Invalid value for yPosition of imagePlacementConfiguration for PdfSignaturePage");
      }
      if (object.getColumns() != null && object.getColumns() > 1 && config.getXIncrement() == null) {
        result.rejectValue("imagePlacementConfiguration.xIncrement",
            "Missing xIncrement of imagePlacementConfiguration for PdfSignaturePage");
      }
      if (object.getRows() != null && object.getRows() > 1 && config.getYIncrement() == null) {
        result.rejectValue("imagePlacementConfiguration.yIncrement",
            "Missing yIncrement of imagePlacementConfiguration for PdfSignaturePage");
      }
    }

    return result;
  }

}
