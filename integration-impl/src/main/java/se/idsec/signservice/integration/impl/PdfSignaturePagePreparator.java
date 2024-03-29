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
package se.idsec.signservice.integration.impl;

import se.idsec.signservice.integration.ExtendedSignServiceIntegrationService;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.error.InputValidationException;
import se.idsec.signservice.integration.core.error.SignServiceIntegrationException;
import se.idsec.signservice.integration.document.pdf.PdfSignaturePageFullException;
import se.idsec.signservice.integration.document.pdf.PdfSignaturePagePreferences;
import se.idsec.signservice.integration.document.pdf.PreparedPdfDocument;

/**
 * Implementation of
 * {@link ExtendedSignServiceIntegrationService#preparePdfSignaturePage(String, byte[], PdfSignaturePagePreferences)}.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface PdfSignaturePagePreparator {

  /**
   * See
   * {@link ExtendedSignServiceIntegrationService#preparePdfSignaturePage(String, byte[], PdfSignaturePagePreferences)}.
   *
   * @param pdfDocument
   *          the contents of the PDF document that is to be prepared
   * @param signaturePagePreferences
   *          the PDF signature page preferences
   * @param policyConfiguration
   *          the policy configuration under which this operation is to be executed
   * @return a PreparedPdfDocument object containing the modified PDF document (if a sign page was added) and the
   *         VisiblePdfSignatureRequirement telling how a signature image should be added
   * @throws InputValidationException
   *           for input validation errors
   * @throws PdfSignaturePageFullException
   *           if the PDF document contains more signatures than there is room for in the PDF signature page (and
   *           {@link PdfSignaturePagePreferences#isFailWhenSignPageFull()} evaluates to true)
   * @throws SignServiceIntegrationException
   *           for other processing errors
   */
  PreparedPdfDocument preparePdfSignaturePage(final byte[] pdfDocument,
      final PdfSignaturePagePreferences signaturePagePreferences,
      final IntegrationServiceConfiguration policyConfiguration)
      throws InputValidationException, PdfSignaturePageFullException, SignServiceIntegrationException;

}
