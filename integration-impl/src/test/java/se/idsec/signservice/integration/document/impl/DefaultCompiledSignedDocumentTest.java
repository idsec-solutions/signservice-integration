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
package se.idsec.signservice.integration.document.impl;

import org.junit.Assert;
import org.junit.Test;

import se.idsec.signservice.integration.document.DocumentProcessingException;
import se.idsec.signservice.integration.document.DocumentType;
import se.idsec.signservice.integration.document.SignedDocument;
import se.idsec.signservice.integration.testbase.TestAdesObject;
import se.idsec.signservice.integration.testbase.TestDocumentEncoderDecoder;
import se.idsec.signservice.integration.testbase.TestDocumentType;

/**
 * Test cases for {@code DefaultCompiledSignedDocument}.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefaultCompiledSignedDocumentTest {

  private static final TestDocumentEncoderDecoder encoder = new TestDocumentEncoderDecoder();

  @Test
  public void testInitErrors() {
    try {
      new DefaultCompiledSignedDocument<TestDocumentType, TestAdesObject>(
          null, new TestDocumentType("Content"), DocumentType.XML.getMimeType(), encoder);
      Assert.fail("Missing id - expected IllegalArgumentException");
    }
    catch (IllegalArgumentException e) {
    }
    try {
      new DefaultCompiledSignedDocument<TestDocumentType, TestAdesObject>("id", null, DocumentType.XML.getMimeType(), encoder);
      Assert.fail("Missing document - expected IllegalArgumentException");
    }
    catch (IllegalArgumentException e) {
    }
    try {
      new DefaultCompiledSignedDocument<TestDocumentType, TestAdesObject>(
          "id", new TestDocumentType("Content"), null, encoder);
      Assert.fail("Missing mimeType - expected IllegalArgumentException");
    }
    catch (IllegalArgumentException e) {
    }
    try {
      new DefaultCompiledSignedDocument<TestDocumentType, TestAdesObject>(
          "id", new TestDocumentType("Content"), DocumentType.XML.getMimeType(), null);
      Assert.fail("Missing document - expected IllegalArgumentException");
    }
    catch (IllegalArgumentException e) {
    }
  }

  @Test
  public void testBasicUse() throws Exception {
    DefaultCompiledSignedDocument<TestDocumentType, TestAdesObject> csd = new DefaultCompiledSignedDocument<>(
        "id", new TestDocumentType("DOCUMENT"), DocumentType.XML.getMimeType(), encoder, new TestAdesObject(null));

    Assert.assertEquals("DOCUMENT", csd.getDocument().getContents());
    Assert.assertNotNull(csd.getAdesObject());

    SignedDocument sd = csd.getSignedDocument();

    Assert.assertEquals("id", sd.getId());
    Assert.assertEquals(DocumentType.XML.getMimeType(), sd.getMimeType());
    Assert.assertNull(sd.getExtension());
    Assert.assertEquals("DOCUMENT", sd.getSignedContent());

    // The document encoding is internally cached. Make sure we get the same result ...
    sd = csd.getSignedDocument();
    Assert.assertEquals("id", sd.getId());
    Assert.assertEquals(DocumentType.XML.getMimeType(), sd.getMimeType());
    Assert.assertNull(sd.getExtension());
    Assert.assertEquals("DOCUMENT", sd.getSignedContent());
  }

  @Test
  public void testErrorDecode() throws Exception {
    TestDocumentEncoderDecoder errEncoder = new TestDocumentEncoderDecoder();
    errEncoder.setFailEncode(true);
    DefaultCompiledSignedDocument<TestDocumentType, TestAdesObject> csd = new DefaultCompiledSignedDocument<>(
        "id", new TestDocumentType("DOCUMENT"), DocumentType.XML.getMimeType(), errEncoder);

    try {
      csd.getSignedDocument();
      Assert.fail("Expected RuntimeException");
    }
    catch (RuntimeException e) {
      Assert.assertTrue(DocumentProcessingException.class.isInstance(e.getCause()));
    }
  }

}
