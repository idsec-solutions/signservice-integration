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
