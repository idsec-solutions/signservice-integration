package se.idsec.signservice.integration.document.pdf.pdfa;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Data class providing status information about PDF document compliance with PDF/A
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PDFAStatus {

  /** Part of PDF/A ISO 19005-1 the document claims conformance to */
  private String part;
  /** Claimed conformance */
  private String conformance;
  /** Indicates if the document is a PDF/A document */
  boolean valid;
}
