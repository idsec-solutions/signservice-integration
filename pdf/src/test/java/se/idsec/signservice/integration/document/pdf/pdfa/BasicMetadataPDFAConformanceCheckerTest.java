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

import org.apache.commons.io.IOUtils;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for the DefaultPDFADeclarationChecker
 */
public class BasicMetadataPDFAConformanceCheckerTest {
  static File pdfFile;
  static File pdfaFile;
  static String pdfaMetadataStr;
  static String noPfdaMetadataStr;
  static String pdfaMetadataAttrStr;
  static PDFAConformanceChecker pdfaConformanceChecker;
  static PDFAConformanceChecker nothingValidPDFAConformanceChecker;

  @BeforeAll
  public static void init() throws Exception {

    pdfFile =
        new File(BasicMetadataPDFAConformanceCheckerTest.class.getClassLoader().getResource("pdfa/Test.pdf").getFile());
    pdfaFile = new File(
        BasicMetadataPDFAConformanceCheckerTest.class.getClassLoader().getResource("pdfa/Test_pdfa.pdf").getFile());
    pdfaMetadataStr = new String(
        IOUtils.toByteArray(Objects.requireNonNull(
            BasicMetadataPDFAConformanceCheckerTest.class.getClassLoader().getResourceAsStream("pdfa/pdfaMetadata"))),
        StandardCharsets.UTF_8);
    pdfaMetadataAttrStr = new String(
        IOUtils.toByteArray(Objects.requireNonNull(
            BasicMetadataPDFAConformanceCheckerTest.class.getClassLoader()
                .getResourceAsStream("pdfa/pdfaMdAttribute"))),
        StandardCharsets.UTF_8);
    noPfdaMetadataStr = new String(
        IOUtils.toByteArray(Objects.requireNonNull(
            BasicMetadataPDFAConformanceCheckerTest.class.getClassLoader().getResourceAsStream("pdfa/noPdfaMetadata"))),
        StandardCharsets.UTF_8);
    pdfaConformanceChecker = new BasicMetadataPDFAConformanceChecker();
    nothingValidPDFAConformanceChecker = new BasicMetadataPDFAConformanceChecker();
    ((BasicMetadataPDFAConformanceChecker) nothingValidPDFAConformanceChecker)
        .setSupportedConformanceValues(Collections.singletonList("A"));
    ((BasicMetadataPDFAConformanceChecker) nothingValidPDFAConformanceChecker)
        .setSupportedPartValues(Collections.singletonList("3"));
  }

  @Test
  public void checkPDFADeclarationFromPdf() throws Exception {

    try (final PDDocument document = Loader.loadPDF(pdfFile)) {
      final PDFAStatus pdfaStatus = pdfaConformanceChecker.checkPDFAConformance(
          document.getDocumentCatalog().getMetadata());
      assertFalse(pdfaStatus.isValid());
    }

    try (final PDDocument document = Loader.loadPDF(pdfaFile)) {
      PDFAStatus pdfaStatus = pdfaConformanceChecker.checkPDFAConformance(
          document.getDocumentCatalog().getMetadata());
      assertTrue(pdfaStatus.isValid());
      assertEquals("2", pdfaStatus.getPart());
      assertEquals("B", pdfaStatus.getConformance());

      pdfaStatus = nothingValidPDFAConformanceChecker.checkPDFAConformance(
          document.getDocumentCatalog().getMetadata());
      assertFalse(pdfaStatus.isValid());
      assertEquals("2", pdfaStatus.getPart());
      assertEquals("B", pdfaStatus.getConformance());
    }
  }

  @Test
  public void checkPdfaMetadata() {
    final PDFAStatus pdfaStatus = ((BasicMetadataPDFAConformanceChecker) pdfaConformanceChecker)
        .checkPDFADeclaration(pdfaMetadataStr);
    assertTrue(pdfaStatus.isValid());
    assertEquals("2", pdfaStatus.getPart());
    assertEquals("B", pdfaStatus.getConformance());
  }

  @Test
  public void checkPdfaMetadataAttr() {
    final PDFAStatus pdfaStatus = ((BasicMetadataPDFAConformanceChecker) pdfaConformanceChecker)
        .checkPDFADeclaration(pdfaMetadataAttrStr);
    assertTrue(pdfaStatus.isValid());
    assertEquals("2", pdfaStatus.getPart());
    assertEquals("B", pdfaStatus.getConformance());
  }

  @Test
  public void checkPdfMetadata() {
    final PDFAStatus pdfaStatus = ((BasicMetadataPDFAConformanceChecker) pdfaConformanceChecker)
        .checkPDFADeclaration(noPfdaMetadataStr);
    assertFalse(pdfaStatus.isValid());
  }

  @Test
  public void checkUnsupportedDeclarations() {
    final PDFAStatus pdfaStatus = ((BasicMetadataPDFAConformanceChecker) nothingValidPDFAConformanceChecker)
        .checkPDFADeclaration(pdfaMetadataStr);
    assertFalse(pdfaStatus.isValid());
    assertEquals("2", pdfaStatus.getPart());
    assertEquals("B", pdfaStatus.getConformance());
  }

}
