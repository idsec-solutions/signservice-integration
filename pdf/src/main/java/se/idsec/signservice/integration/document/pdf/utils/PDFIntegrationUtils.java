package se.idsec.signservice.integration.document.pdf.utils;

import se.idsec.signservice.integration.document.TbsDocument;
import se.idsec.signservice.security.sign.AdesProfileType;

/**
 * Utilities for PDF integration implementations.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class PDFIntegrationUtils {

  /**
   * Get the {@link AdesProfileType} for a PAdES requirement in a {@link TbsDocument}.
   * 
   * @param requestedAdes
   *          AdES requirement
   * @return enum the AdES requirement
   */
  public static AdesProfileType getPadesRequirement(final TbsDocument.EtsiAdesRequirement requestedAdes) {
    if (requestedAdes != null) {
      final TbsDocument.AdesType adesType = requestedAdes.getAdesFormat();
      if (TbsDocument.AdesType.BES.equals(adesType)) {
        return AdesProfileType.BES;
      }
      else if (TbsDocument.AdesType.EPES.equals(adesType)) {
        return AdesProfileType.EPES;
      }
    }
    return AdesProfileType.None; 
  }

  private PDFIntegrationUtils() {
  }

}
