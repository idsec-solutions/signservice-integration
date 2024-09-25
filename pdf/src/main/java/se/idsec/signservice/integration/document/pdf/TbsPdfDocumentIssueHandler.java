/*
 * Copyright 2019-2024 IDsec Solutions AB
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

import jakarta.annotation.Nonnull;
import lombok.extern.slf4j.Slf4j;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import se.idsec.signservice.integration.core.error.ErrorCode;
import se.idsec.signservice.integration.document.DocumentProcessingException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Processes documents to be signed for issues that would prevent the document from being signed successfully.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class TbsPdfDocumentIssueHandler {

  /**
   * Default constructor.
   */
  public TbsPdfDocumentIssueHandler() {
  }

  /**
   * Checks the supplied document for the presence of Acroforms and encryption dictionaries. If the supplied
   * {@code settings} parameter indicated that these issues should be fixed, the method will perform the fixes and
   * indicate what has been fixed in the result. If no issues needed fixing, an empty list of actions will be returned.
   * <p>
   * If fixing of detected issues is not configured, a corresponding exception will be thrown.
   * </p>
   *
   * @param document the document to fix
   * @param settings settings for preparation of PDF documents
   * @return a (potentially empty) list of actions that were fixed
   * @throws DocumentProcessingException if the document can not be loaded or if fixing of issues fails
   * @throws PdfContainsAcroformException if fixing of Acroforms is not configured and an Acroform is detected
   * @throws PdfContainsEncryptionDictionaryException if fixing of encryption dictionaries is not configured and an
   *     encryption dictionary is detected
   */
  @Nonnull
  public List<PdfPrepareReport.PrepareActions> fixIssues(
      @Nonnull final PDDocument document, @Nonnull final PdfPrepareSettings settings)
      throws DocumentProcessingException, PdfContainsAcroformException, PdfContainsEncryptionDictionaryException {

    final List<PdfPrepareReport.PrepareActions> result = new ArrayList<>();

    if (document.getEncryption() != null) {
      final String msg = "Document contains encryption dictionary";
      if (!settings.isAllowRemoveEncryptionDictionary()) {
        throw new PdfContainsEncryptionDictionaryException("%s - not configured to remove".formatted(msg));
      }
      log.info("{} - Removing protection policy and encryption dictionary", msg);
      document.setAllSecurityToBeRemoved(true);

      result.add(PdfPrepareReport.PrepareActions.REMOVED_ENCRYPTION_DICTIONARY);
    }

    if (document.getSignatureDictionaries().isEmpty() && document.getDocumentCatalog().getAcroForm() != null) {
      final String msg = "Document contains AcroForm";

      if (!settings.isAllowFlattenAcroForms()) {
        throw new PdfContainsAcroformException("%s - not configured to flatten".formatted(msg));
      }
      log.info("{} - Flattening ...", msg);
      try {
        final PDAcroForm acroForm = document.getDocumentCatalog().getAcroForm();
        acroForm.flatten();
        document.getDocumentCatalog().setAcroForm(null);
        log.info("Flattened and removed AcroForm");

        result.add(PdfPrepareReport.PrepareActions.FLATTENED_ACROFORM);
      }
      catch (final IOException e) {
        throw new DocumentProcessingException(new ErrorCode.Code("pdf-flatten-acroform-failed"),
            "Failed to flatten AcroForm", e);
      }
    }

    if (result.isEmpty()) {
      log.debug("No issues found in PDF document that needed action");
    }

    return result;
  }

}
