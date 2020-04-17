package se.idsec.signservice.integration.document.pdf.utils;

import se.idsec.signservice.integration.document.TbsDocument;
import se.idsec.signservice.security.sign.pdf.document.PDFSignTaskDocument;

public class PdfIntegrationUtils {

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
