package se.idsec.signservice.integration.document.pdf;

import lombok.extern.slf4j.Slf4j;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.springframework.util.CollectionUtils;
import se.idsec.signservice.integration.core.error.ErrorCode;
import se.idsec.signservice.integration.document.DocumentProcessingException;
import se.idsec.signservice.integration.document.pdf.utils.PDDocumentUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Process documents to be signed for issues that would prevent the document from being signed successfully.
 * <p>
 * This offers one function to identify issues and another to selectively fix identified issues.
 * This allows a service to first identify issues and then decide whether to fix them or to reject the signing process.
 * This option to reject instead of fixing can be important as fixing these issues inherently means applying changes to
 * the document to be signed.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class TbsPdfDocumentIssueHandler {

  /**
   * Creates a new instance of TbsPdfDocumentIssueHandler.
   */
  public TbsPdfDocumentIssueHandler() {
  }

  /**
   * Identifies the fixable issues in a given PDF document.
   *
   * @param pdfDocument the bytes of the PDF document to identify issues in
   * @return a list of fixable issues found in the PDF document
   */
  public List<PdfDocumentIssue> identifyFixableIssues(byte[] pdfDocument) throws DocumentProcessingException {
    PDDocument pdDocument = PDDocumentUtils.load(pdfDocument);
    try {
      return identifyFixableIssues(pdDocument);
    } finally {
      PDDocumentUtils.close(pdDocument);
    }
  }

  /**
   * Identifies the fixable issues in a given PDF document.
   *
   * @param pdfDocument the PDF document to identify issues in
   * @return a list of fixable issues found in the PDF document
   */
  public List<PdfDocumentIssue> identifyFixableIssues(PDDocument pdfDocument) {
    List<PdfDocumentIssue> pdfDocumentIssues = new ArrayList<>();
    boolean unsigned = CollectionUtils.isEmpty(pdfDocument.getSignatureDictionaries());
    if (!unsigned) {
      // We cant fix any issues in a signed document. That would break the signature.
      return List.of();
    }
    if (pdfDocument.getEncryption() != null) {
      pdfDocumentIssues.add(PdfDocumentIssue.ENCRYPTION_DICTIONARY);
    }
    if (pdfDocument.getDocumentCatalog().getAcroForm() != null) {
      pdfDocumentIssues.add(PdfDocumentIssue.ACROFORM_IN_UNSIGNED_PDF);
    }
    return pdfDocumentIssues;
  }

  /**
   * Fixes the issues in a PDF document and returns the fixed document as a byte array.
   *
   * @param pdfDocument the original PDF document as a byte array
   * @param issues a list issues to be fixed if present
   * @return the fixed PDF document as a byte array
   * @throws DocumentProcessingException If an error occurs while processing the document.
   */
  public byte[] fixIssues(byte[] pdfDocument, List<PdfDocumentIssue> issues) throws DocumentProcessingException {
    if (CollectionUtils.isEmpty(issues)) {
      // Nothing to do. Return the input bytes.
      return pdfDocument;
    }
    PDDocument pdDocument = PDDocumentUtils.load(pdfDocument);
    try {
      fixIssues(pdDocument, issues);
      return PDDocumentUtils.toBytes(pdDocument);
    } finally {
      PDDocumentUtils.close(pdDocument);
    }
  }

  /**
   * Fixes identified issues in a PDF document.
   *
   * @param pdfDocument the PDF document to be fixed
   * @param issues a list issues to be fixed if present
   * @throws DocumentProcessingException if an error occurs during the document processing
   */
  public void fixIssues(PDDocument pdfDocument, List<PdfDocumentIssue> issues) throws DocumentProcessingException {
    List<PdfDocumentIssue> identifiedIssues = identifyFixableIssues(pdfDocument);
    for (PdfDocumentIssue issue : issues) {
      switch (issue) {
      case ENCRYPTION_DICTIONARY -> {
        // Only fix if the problem that actually exists
        if (identifiedIssues.contains(PdfDocumentIssue.ENCRYPTION_DICTIONARY)) {
          pdfDocument.setAllSecurityToBeRemoved(true);
          log.debug("Removing protection policy and encryption dictionary");
        }
      }
      case ACROFORM_IN_UNSIGNED_PDF -> {
        // Only fix if the problem that actually exists
        if (identifiedIssues.contains(PdfDocumentIssue.ACROFORM_IN_UNSIGNED_PDF)) {
          PDAcroForm acroForm = pdfDocument.getDocumentCatalog().getAcroForm();
          try {
            acroForm.flatten();
          }
          catch (IOException e) {
            throw new DocumentProcessingException(new ErrorCode.Code("document-issues") ,"Failed to flatten AcroForm", e);
          }
          pdfDocument.getDocumentCatalog().setAcroForm(null);
          log.debug("Flattened and removed AcroForm");
        }
      }
      }
    }
  }

}
