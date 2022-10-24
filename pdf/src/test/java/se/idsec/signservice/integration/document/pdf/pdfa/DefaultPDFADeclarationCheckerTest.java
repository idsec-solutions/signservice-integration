/*
 * Copyright 2019-2022 IDsec Solutions AB
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

import junit.framework.TestCase;
import org.apache.commons.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Objects;

/**
 * Tests for the DefaultPDFADeclarationChecker
 */
@RunWith(JUnit4.class)
public class DefaultPDFADeclarationCheckerTest extends TestCase {
  static File pdfFile;
  static File pdfaFile;
  static String pdfaMetadataStr;
  static String noPfdaMetadataStr;
  static String pdfaMetadataAttrStr;
  static PDFADeclarationChecker pdfaDeclarationChecker;
  static PDFADeclarationChecker nothingValidPDFADeclarationChecker;

  @BeforeClass
  public static void init() throws Exception {

    pdfFile = new File(DefaultPDFADeclarationCheckerTest.class.getClassLoader().getResource("pdfa/Test.pdf").getFile());
    pdfaFile = new File(DefaultPDFADeclarationCheckerTest.class.getClassLoader().getResource("pdfa/Test_pdfa.pdf").getFile());
    pdfaMetadataStr = new String(
      IOUtils.toByteArray(Objects.requireNonNull(
        DefaultPDFADeclarationCheckerTest.class.getClassLoader().getResourceAsStream("pdfa/pdfaMetadata"))),
      StandardCharsets.UTF_8
    );
    pdfaMetadataAttrStr = new String(
      IOUtils.toByteArray(Objects.requireNonNull(
        DefaultPDFADeclarationCheckerTest.class.getClassLoader().getResourceAsStream("pdfa/pdfaMdAttribute"))),
      StandardCharsets.UTF_8
    );
    noPfdaMetadataStr = new String(
      IOUtils.toByteArray(Objects.requireNonNull(
        DefaultPDFADeclarationCheckerTest.class.getClassLoader().getResourceAsStream("pdfa/noPdfaMetadata"))),
      StandardCharsets.UTF_8
    );
    pdfaDeclarationChecker = new DefaultPDFADeclarationChecker();
    nothingValidPDFADeclarationChecker = new DefaultPDFADeclarationChecker();
    ((DefaultPDFADeclarationChecker)nothingValidPDFADeclarationChecker).setSupportedConformanceValues(Collections.singletonList("A"));
    ((DefaultPDFADeclarationChecker)nothingValidPDFADeclarationChecker).setSupportedPartValues(Collections.singletonList("3"));
  }

  @Test
  public void checkPDFADeclarationFromPdf() throws Exception{

    try (PDDocument document = PDDocument.load(pdfFile)){
      PDFAStatus pdfaStatus = pdfaDeclarationChecker.checkPDFADeclaration(
        document.getDocumentCatalog().getMetadata());
      assertFalse(pdfaStatus.isValid());
    }

    try (PDDocument document = PDDocument.load(pdfaFile)){
      PDFAStatus pdfaStatus = pdfaDeclarationChecker.checkPDFADeclaration(
        document.getDocumentCatalog().getMetadata());
      assertTrue(pdfaStatus.isValid());
      assertEquals("2", pdfaStatus.getPart());
      assertEquals("B", pdfaStatus.getConformance());

      pdfaStatus = nothingValidPDFADeclarationChecker.checkPDFADeclaration(
        document.getDocumentCatalog().getMetadata());
      assertFalse(pdfaStatus.isValid());
      assertEquals("2", pdfaStatus.getPart());
      assertEquals("B", pdfaStatus.getConformance());
    }
  }

  @Test
  public void checkPdfaMetadata() {
    PDFAStatus pdfaStatus = ((DefaultPDFADeclarationChecker) pdfaDeclarationChecker)
      .checkPDFADeclaration(pdfaMetadataStr);
    assertTrue(pdfaStatus.isValid());
    assertEquals("2", pdfaStatus.getPart());
    assertEquals("B", pdfaStatus.getConformance());
  }

  @Test
  public void checkPdfaMetadataAttr() {
    PDFAStatus pdfaStatus = ((DefaultPDFADeclarationChecker) pdfaDeclarationChecker)
      .checkPDFADeclaration(pdfaMetadataAttrStr);
    assertTrue(pdfaStatus.isValid());
    assertEquals("2", pdfaStatus.getPart());
    assertEquals("B", pdfaStatus.getConformance());
  }

  @Test
  public void checkPdfMetadata() {
    PDFAStatus pdfaStatus = ((DefaultPDFADeclarationChecker) pdfaDeclarationChecker)
      .checkPDFADeclaration(noPfdaMetadataStr);
    assertFalse(pdfaStatus.isValid());
  }

  @Test
  public void checkUnsupportedDeclarations() {
    PDFAStatus pdfaStatus = ((DefaultPDFADeclarationChecker) nothingValidPDFADeclarationChecker)
      .checkPDFADeclaration(pdfaMetadataStr);
    assertFalse(pdfaStatus.isValid());
    assertEquals("2", pdfaStatus.getPart());
    assertEquals("B", pdfaStatus.getConformance());
  }

}