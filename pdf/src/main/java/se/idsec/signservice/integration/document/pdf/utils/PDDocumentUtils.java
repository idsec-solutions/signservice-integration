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

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Iterator;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;

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

  /**
   * Encodes the supplied PDF document into a byte array.
   * 
   * @param document
   *          the document to encode
   * @return a byte array of the contents
   * @throws DocumentProcessingException
   *           for processing errors
   */
  public static byte[] toBytes(final PDDocument document) throws DocumentProcessingException {
    try {
      final ByteArrayOutputStream bos = new ByteArrayOutputStream();
      final BufferedOutputStream os = new BufferedOutputStream(bos);
      document.save(os);
      return bos.toByteArray();
    }
    catch (IOException e) {
      throw new DocumentProcessingException(new ErrorCode.Code("encode"), "Failed to encode PDF document", e);
    }
  }

  /**
   * Inserts the {@code insertDocument} in {@code document} at position {@code page} (1-based). This means that the
   * given page number is the page number for the first page of the {@code insertDocument} after insertion.
   * 
   * @param document
   *          the document to be updated
   * @param insertDocument
   *          the document to insert
   * @param page
   *          the page (1-based) number where to insert, 0 means at the end of the file
   * @throws DocumentProcessingException
   *           for errors
   */
  public static void insertDocument(final PDDocument document, final PDDocument insertDocument, final int page)
      throws DocumentProcessingException {
    try {
      final int documentNumberOfPages = document.getNumberOfPages();

      PDPage insert = page == 0 || page == documentNumberOfPages + 1
          ? document.getPage(documentNumberOfPages - 1)
          : document.getPage(page - 1);
      boolean insertAfter = (page == 0 || page == documentNumberOfPages + 1) ? true : false;

      final Iterator<PDPage> it = insertDocument.getPages().iterator();
      while (it.hasNext()) {
        PDPage newPage = it.next();
        if (insertAfter) {
          document.getPages().insertAfter(newPage, insert);
        }
        else {
          document.getPages().insertBefore(newPage, insert);
          insertAfter = true;
        }
        insert = newPage;
      }
    }
    catch (IndexOutOfBoundsException | IllegalStateException | IllegalArgumentException e) {
      throw new DocumentProcessingException(new ErrorCode.Code("pdf"),
        String.format("Failed to insert sign page at page %d of document (no such page)", page), e);
    }

  }

  private PDDocumentUtils() {
  }

}
