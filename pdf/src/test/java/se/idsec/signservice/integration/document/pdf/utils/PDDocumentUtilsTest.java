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

import java.io.IOException;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

/**
 * Test cases for PDDocumentUtils.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class PDDocumentUtilsTest {

  @Test
  public void testAppend() throws Exception {
    PDDocument doc = null;
    PDDocument ins = null;
    try {
      doc = load("pdf/four-pages.pdf");
      ins = load("pdf/one-page.pdf");

      doc = PDDocumentUtils.insertDocument(doc, ins, 0);

      Assertions.assertEquals(5, doc.getNumberOfPages());
      Assertions.assertTrue(getContents(doc, 5).contains("Document 1: This is page one"));
    }
    finally {
      PDDocumentUtils.close(doc);
      PDDocumentUtils.close(ins);
    }
  }

  @Test
  public void testAppend2() throws Exception {
    PDDocument doc = null;
    PDDocument ins = null;
    try {
      doc = load("pdf/four-pages.pdf");
      ins = load("pdf/one-page.pdf");

      doc = PDDocumentUtils.insertDocument(doc, ins, 5);  // 5 is the new page number

      Assertions.assertEquals(5, doc.getNumberOfPages());
      Assertions.assertTrue(getContents(doc, 4).contains("Document 4: This is page four"));
      Assertions.assertTrue(getContents(doc, 5).contains("Document 1: This is page one"));
    }
    finally {
      PDDocumentUtils.close(doc);
      PDDocumentUtils.close(ins);
    }
  }

  @Test
  public void testInsertMultipageFirst() throws Exception {
    PDDocument doc = null;
    PDDocument ins = null;
    try {
      doc = load("pdf/four-pages.pdf");
      ins = load("pdf/two-pages.pdf");

      doc = PDDocumentUtils.insertDocument(doc, ins, 1);

      Assertions.assertEquals(6, doc.getNumberOfPages());
      Assertions.assertTrue(getContents(doc, 1).contains("Document 2: This is page one"));
      Assertions.assertTrue(getContents(doc, 2).contains("Document 2: This is page two"));
      Assertions.assertTrue(getContents(doc, 3).contains("Document 4: This is page one"));
    }
    finally {
      PDDocumentUtils.close(doc);
      PDDocumentUtils.close(ins);
    }
  }

  @Test
  public void testInsertMultipageMiddle() throws Exception {
    PDDocument doc = null;
    PDDocument ins = null;
    try {
      doc = load("pdf/four-pages.pdf");
      ins = load("pdf/two-pages.pdf");

      doc = PDDocumentUtils.insertDocument(doc, ins, 3);

      Assertions.assertEquals(6, doc.getNumberOfPages());
      Assertions.assertTrue(getContents(doc, 2).contains("Document 4: This is page two"));
      Assertions.assertTrue(getContents(doc, 3).contains("Document 2: This is page one"));
      Assertions.assertTrue(getContents(doc, 4).contains("Document 2: This is page two"));
      Assertions.assertTrue(getContents(doc, 5).contains("Document 4: This is page three"));
    }
    finally {
      PDDocumentUtils.close(doc);
      PDDocumentUtils.close(ins);
    }
  }

  private static PDDocument load(final String resource) throws IOException {
    return Loader.loadPDF((new ClassPathResource(resource)).getFile());
  }

  private static String getContents(final PDDocument doc, final int page) throws IOException {
    final PDFTextStripper reader = new PDFTextStripper();
    reader.setStartPage(page);
    reader.setEndPage(page);
    return reader.getText(doc);
  }

}
