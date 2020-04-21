package se.idsec.signservice.integration.document.pdf.utils;

import se.idsec.signservice.integration.document.TbsDocument;
import se.idsec.signservice.security.sign.pdf.document.PDFSignTaskDocument;

/**
 * Utilities for PDF integration implementations
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class PDFIntegrationUtils {
  /**
   * Get the string identifier for a PAdES requirement in a {@link TbsDocument}
   * @param requestedAdes AdES requirement
   * @return string representation of the AdES requirement
   */
  public static String getPadesRequirementString(TbsDocument.EtsiAdesRequirement requestedAdes){
    String ades = PDFSignTaskDocument.ADES_PROFILE_NONE;
    if (requestedAdes != null){
      TbsDocument.AdesType adesType = requestedAdes.getAdesFormat();
      if (adesType.equals(TbsDocument.AdesType.BES)){
        ades = PDFSignTaskDocument.ADES_PROFILE_BES;
      }
      if (adesType.equals(TbsDocument.AdesType.EPES)){
        ades = PDFSignTaskDocument.ADES_PROFILE_EPES;
      }
    }
    return ades;
  }
}
