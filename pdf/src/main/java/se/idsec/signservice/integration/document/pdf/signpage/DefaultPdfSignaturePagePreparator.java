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
package se.idsec.signservice.integration.document.pdf.signpage;

import org.apache.pdfbox.pdmodel.PDDocument;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.ExtendedSignServiceIntegrationService;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.error.InputValidationException;
import se.idsec.signservice.integration.core.error.SignServiceIntegrationException;
import se.idsec.signservice.integration.document.DocumentProcessingException;
import se.idsec.signservice.integration.document.pdf.PdfSignaturePageFullException;
import se.idsec.signservice.integration.document.pdf.PdfSignaturePagePreferences;
import se.idsec.signservice.integration.document.pdf.PreparedPdfDocument;
import se.idsec.signservice.integration.document.pdf.signpage.impl.PdfSignaturePagePreferencesValidator;
import se.idsec.signservice.integration.document.pdf.utils.PDDocumentUtils;
import se.idsec.signservice.integration.impl.PdfSignaturePagePreparator;

/**
 * Implementation of the
 * {@link ExtendedSignServiceIntegrationService#preparePdfSignaturePage(String, byte[], PdfSignaturePagePreferences)}
 * method.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class DefaultPdfSignaturePagePreparator implements PdfSignaturePagePreparator {

  /** Validator for PdfSignaturePagePreferences objects. */
  private PdfSignaturePagePreferencesValidator pdfSignaturePagePreferencesValidator = new PdfSignaturePagePreferencesValidator();

  /** {@inheritDoc} */
  @Override
  public PreparedPdfDocument preparePdfSignaturePage(final byte[] pdfDocument,
      final PdfSignaturePagePreferences signaturePagePreferences,
      final IntegrationServiceConfiguration policyConfiguration)
      throws InputValidationException, PdfSignaturePageFullException, SignServiceIntegrationException {

    // First validate the input ...
    //
    this.validateInput(pdfDocument, signaturePagePreferences, policyConfiguration);

    // Load the PDF document and check if it already has signatures (we assume that there is a PDF signature page and
    // that each signature has a signature image).
    //
    final PDDocument document = PDDocumentUtils.load(pdfDocument); 

    return null;
  }

  /**
   * Validates the input supplied to
   * {@link #preparePdfSignaturePage(byte[], PdfSignaturePagePreferences, IntegrationServiceConfiguration)}.
   * 
   * @param pdfDocument
   *          the PDF document
   * @param signaturePagePreferences
   *          the signature page preferences
   * @param policyConfiguration
   *          the policy configuration
   * @throws InputValidationException
   *           for validation errors
   */
  private void validateInput(final byte[] pdfDocument,
      final PdfSignaturePagePreferences signaturePagePreferences,
      final IntegrationServiceConfiguration policyConfiguration)
      throws InputValidationException {

    if (pdfDocument == null) {
      throw new InputValidationException("pdfDocument", "Missing pdfDocument");
    }
    if (signaturePagePreferences == null) {
      throw new InputValidationException("signaturePagePreferences", "Missing signaturePagePreferences");
    }
    if (policyConfiguration == null) {
      throw new InputValidationException("policy", "Can not find policy");
    }
    this.pdfSignaturePagePreferencesValidator.validateObject(signaturePagePreferences, "signaturePagePreferences", policyConfiguration);

    // Update the preferences with settings from the config (if needed) ...
    // Note: No checks need to be applied since the validator would have failed if there is something missing.
    //
    if (signaturePagePreferences.getSignaturePageReference() == null && signaturePagePreferences.getSignaturePage() == null) {
      signaturePagePreferences.setSignaturePage(policyConfiguration.getPdfSignaturePages().get(0));
      log.debug("Using default PdfSignaturePage ({}) for policy '{}'",
        signaturePagePreferences.getSignaturePage().getId(), policyConfiguration.getPolicy());
    }
    if (signaturePagePreferences.getSignaturePageReference() != null) {
      signaturePagePreferences.setSignaturePage(policyConfiguration.getPdfSignaturePages().stream()
        .filter(p -> signaturePagePreferences.getSignaturePageReference().equals(p.getId()))
        .findFirst()
        .orElse(null));
    }
    
    // The core libraries do not have access to PDFBox so we can't trust the validators for the configuration
    // to check if the PDFSignaturePage is a valid PDF document. Let's do it here ...
    //
    PDDocument document = null;
    try {
      document = PDDocumentUtils.load(pdfDocument);
    }
    catch (DocumentProcessingException e) {
      throw new InputValidationException("signaturePagePreferences.signaturePage", "Invalid PdfSignaturePage - not a valid PDF document");
    }
    finally {
      PDDocumentUtils.close(document);
    }

  }

}
