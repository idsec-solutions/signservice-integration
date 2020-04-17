package se.idsec.signservice.integration.document.pdf.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.util.encoders.Base64;
import se.idsec.signservice.integration.document.TbsDocument;
import se.idsec.signservice.pdf.sign.PDFSignTaskDocument;
import se.idsec.signservice.pdf.sign.VisibleSigImage;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.logging.Logger;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

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
