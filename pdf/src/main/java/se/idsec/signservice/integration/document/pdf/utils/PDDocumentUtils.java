/*
 * Copyright 2019-2025 IDsec Solutions AB
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

import lombok.extern.slf4j.Slf4j;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdfwriter.compress.CompressParameters;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageTree;
import se.idsec.signservice.integration.core.error.ErrorCode;
import se.idsec.signservice.integration.document.DocumentProcessingException;
import se.idsec.signservice.integration.document.pdf.pdfa.BasicMetadataPDFAConformanceChecker;
import se.idsec.signservice.integration.document.pdf.pdfa.PDFAConformanceChecker;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Utility methods for working with {@link PDDocument} objects.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class PDDocumentUtils {

  public static final PDFAConformanceChecker pdfaChecker = new BasicMetadataPDFAConformanceChecker();

  /**
   * Loads a {@link PDDocument} given its byte contents.
   * <p>
   * The returned object must later be closes (see {@link #close(PDDocument)}).
   * </p>
   *
   * @param contents the PDF file contents
   * @return a loaded PDDocument object
   * @throws DocumentProcessingException for loading errors
   */
  public static PDDocument load(final byte[] contents) throws DocumentProcessingException {
    try {
      return Loader.loadPDF(contents);
    }
    catch (final IOException e) {
      log.error("Failed to load PDF document", e);
      throw new DocumentProcessingException(new ErrorCode.Code("decode"), "Failed to load PDF object", e);
    }
  }

  /**
   * Closes an open {@link PDDocument} object and releases its allocated resources.
   *
   * @param document the document to close
   */
  public static void close(final PDDocument document) {
    if (document != null) {
      try {
        document.close();
      }
      catch (final IOException e) {
        log.warn("Failed to close PDDocument object", e);
      }
    }
  }

  /**
   * Encodes the supplied PDF document into a byte array.
   *
   * @param document the document to encode
   * @return a byte array of the contents
   * @throws DocumentProcessingException for processing errors
   */
  public static byte[] toBytes(final PDDocument document) throws DocumentProcessingException {
    try (final ByteArrayOutputStream bos = new ByteArrayOutputStream();
        final BufferedOutputStream os = new BufferedOutputStream(bos)) {
      document.save(os, CompressParameters.NO_COMPRESSION);
      os.flush();
      return bos.toByteArray();
    }
    catch (final IOException e) {
      throw new DocumentProcessingException(new ErrorCode.Code("encode"), "Failed to encode PDF document", e);
    }
  }

  /**
   * Inserts the {@code insertDocument} in {@code document} at position {@code page} (1-based). This means that the
   * given page number is the page number for the first page of the {@code insertDocument} after insertion.
   *
   * @param document the document to be updated (will be closed)
   * @param insertDocument the document to insert
   * @param page the page (1-based) number where to insert, 0 means at the end of the file
   * @return the updated document
   * @throws DocumentProcessingException for errors
   */
  public static PDDocument insertDocument(final PDDocument document, final PDDocument insertDocument, final int page)
      throws DocumentProcessingException {
    try {
      final int documentNumberOfPages = document.getNumberOfPages();
      final int pagesToAdd = insertDocument.getNumberOfPages();
      final boolean append = page == 0 || page == documentNumberOfPages + 1;

      for (final PDPage pdPage : insertDocument.getPages()) {
        document.importPage(pdPage);
      }

      if (!append) {
        final PDPageTree tree = document.getPages();
        final List<PDPage> newPages = new ArrayList<>();
        for (int i = 0; i < pagesToAdd; i++) {
          newPages.add(tree.get(documentNumberOfPages + i));
        }
        int pageCount = documentNumberOfPages + pagesToAdd;
        while (pageCount > documentNumberOfPages) {
          tree.remove(--pageCount);
        }
        int insertionPos = page - 1;
        for (final PDPage newPage : newPages) {
          tree.insertBefore(newPage, tree.get(insertionPos));
          insertionPos++;
        }
      }

      return PDDocumentUtils.load(PDDocumentUtils.toBytes(document));
    }
    catch (final IndexOutOfBoundsException | IllegalStateException | IllegalArgumentException e) {
      throw new DocumentProcessingException(new ErrorCode.Code("pdf"),
          String.format("Failed to insert sign page at page %d of document (no such page)", page), e);
    }
    catch (final IOException e) {
      throw new DocumentProcessingException(new ErrorCode.Code("pdf"), "Failed to insert sign page into document", e);
    }
    finally {
      PDDocumentUtils.close(document);
    }
  }

  private PDDocumentUtils() {
  }

}
