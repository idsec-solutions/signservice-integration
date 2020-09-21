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

import java.io.IOException;

import org.apache.pdfbox.pdmodel.PDDocument;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.core.error.ErrorCode;
import se.idsec.signservice.integration.document.DocumentProcessingException;

/**
 * Utility methods for working with {@link PDDocument} objects.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class PDDocumentUtils {

  /**
   * Loads a {@link PDDocument} given its byte contents.
   * <p>
   * The returned object must later be closes (see {@link #close(PDDocument)}).
   * </p>
   * 
   * @param contents
   *          the PDF file contents
   * @return a loaded PDDocument object
   * @throws DocumentProcessingException
   *           for loading errors
   */
  public static PDDocument load(final byte[] contents) throws DocumentProcessingException {
    try {
      return PDDocument.load(contents);
    }
    catch (IOException e) {
      log.error("Failed to load PDF document", e);
      throw new DocumentProcessingException(new ErrorCode.Code("decode"), "Failed to load PDF object", e);
    }
  }

  /**
   * Closes an open {@link PDDocument} object and releases its allocated resources.
   * 
   * @param document
   *          the document to close
   */
  public static void close(final PDDocument document) {
    if (document != null) {
      try {
        document.close();
      }
      catch (IOException e) {
        log.warn("Failed to close PDDocument object", e);
      }
    }
  }

  private PDDocumentUtils() {
  }

}
