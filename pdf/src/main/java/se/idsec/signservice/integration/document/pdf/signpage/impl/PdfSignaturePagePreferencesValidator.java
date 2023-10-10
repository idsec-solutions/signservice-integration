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
package se.idsec.signservice.integration.document.pdf.signpage.impl;

import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.validation.AbstractInputValidator;
import se.idsec.signservice.integration.core.validation.ValidationResult;
import se.idsec.signservice.integration.document.impl.PdfSignaturePageValidator;
import se.idsec.signservice.integration.document.impl.VisiblePdfSignatureUserInformationValidator;
import se.idsec.signservice.integration.document.pdf.PdfSignatureImageTemplate;
import se.idsec.signservice.integration.document.pdf.PdfSignaturePage;
import se.idsec.signservice.integration.document.pdf.PdfSignaturePagePreferences;

/**
 * Validator for {@link PdfSignaturePagePreferences} objects.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class PdfSignaturePagePreferencesValidator
    extends AbstractInputValidator<PdfSignaturePagePreferences, IntegrationServiceConfiguration> {

  /** Validator for sign pages. */
  private PdfSignaturePageValidator pdfSignaturePageValidator = new ExtendedPdfSignaturePageValidator();

  /** Validator for VisiblePdfSignatureUserInformation objects. */
  private VisiblePdfSignatureUserInformationValidator visiblePdfSignatureUserInformationValidator =
      new VisiblePdfSignatureUserInformationValidator();

  /** {@inheritDoc} */
  @Override
  public ValidationResult validate(
      final PdfSignaturePagePreferences object, final String objectName, final IntegrationServiceConfiguration hint) {

    final ValidationResult result = new ValidationResult(objectName);
    if (object == null) {
      return result;
    }

    PdfSignaturePage page = null;
    if (object.getSignaturePageReference() == null && object.getSignaturePage() == null) {
      // OK, see if we have one in the configuration.
      if (hint.getPdfSignaturePages() != null && !hint.getPdfSignaturePages().isEmpty()) {
        page = hint.getPdfSignaturePages().get(0);
      }
      if (page == null) {
        result.reject("No signaturePageReference or signaturePage given, and no default page found in config.");
        return result;
      }
    }
    else if (object.getSignaturePageReference() != null && object.getSignaturePage() != null) {
      result.reject("Invalid object - Not both signaturePageReference and signaturePage can be given");
      return result;
    }
    else if (object.getSignaturePageReference() != null) {
      // Find the sign page ...
      page = hint.getPdfSignaturePages().stream()
          .filter(p -> object.getSignaturePageReference().equals(p.getId()))
          .findAny()
          .orElse(null);
      if (page == null) {
        result.rejectValue("signaturePageReference",
            String.format("Configuration '%s' does not hold a PdfSignaturePage with id '%s'", hint.getPolicy(),
                object.getSignaturePageReference()));
      }
    }
    else if (object.getSignaturePage() != null) {
      result.setFieldErrors(
          this.pdfSignaturePageValidator.validate(object.getSignaturePage(), "signaturePage",
              hint.getPdfSignatureImageTemplates()));
      page = object.getSignaturePage();
    }

    if (object.getVisiblePdfSignatureUserInformation() == null) {
      result.rejectValue("visiblePdfSignatureUserInformation", "Missing visiblePdfSignatureUserInformation");
    }
    else {
      PdfSignatureImageTemplate template = null;
      if (page != null) {
        final PdfSignaturePage _page = page;
        template = hint.getPdfSignatureImageTemplates().stream()
            .filter(t -> _page.getSignatureImageReference().equals(t.getReference()))
            .findFirst()
            .orElse(null);
      }
      if (template != null || object.getSignaturePageReference() != null) {
        result.setFieldErrors(
            this.visiblePdfSignatureUserInformationValidator.validate(
                object.getVisiblePdfSignatureUserInformation(), "visiblePdfSignatureUserInformation", template));
      }
    }

    return result;
  }

}
