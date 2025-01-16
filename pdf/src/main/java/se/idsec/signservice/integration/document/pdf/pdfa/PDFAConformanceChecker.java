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
package se.idsec.signservice.integration.document.pdf.pdfa;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.common.PDMetadata;
import se.idsec.signservice.integration.document.pdf.PdfAConsistencyCheckException;

/**
 * Interface for testing PDF/A conformance
 *
 * <p>
 * Implementations of this interface may provide different level of compliance testing, from just checking compliance
 * declarations to different levels of conformance checking.
 * </p>
 */
public interface PDFAConformanceChecker {

  /**
   * Examines PDF document metadata for declarations that this PDF is compliant with the PDF/A profile.
   *
   * @param metadata PDF document metadata
   * @return PDF/A declaration data
   */
  PDFAStatus checkPDFAConformance(final PDMetadata metadata);

  /**
   * Predicate that tells whether the {@code tbsDoc} and the {@code signPage} is "consistent", meaning that the method
   * will return {@code false} the main document is PDF/A and the added sign page is not, and {@code true} otherwise
   *
   * @param tbsDoc the pdf document to be signed
   * @param signPage the sign page added to the document to be signed
   * @return {@code true} if constistent and {@code false otherwise}
   */
  boolean isPDFAConsistent(final PDDocument tbsDoc, final PDDocument signPage);

  /**
   * Check PDF/A consistency between the main document to be signed and a sign page added to the main document.
   *
   * @param tbsDoc the pdf document to be signed
   * @param signPage the sign page added to the document to be signed
   * @throws PdfAConsistencyCheckException if the main document is PDF/A and the added sign page is not
   */
  void assertPDFAConsistency(final PDDocument tbsDoc, final PDDocument signPage) throws PdfAConsistencyCheckException;
}
