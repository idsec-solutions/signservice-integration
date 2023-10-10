/*
 * Copyright 2019-2023 IDsec Solutions AB
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
   * @param requestedAdes AdES requirement
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
