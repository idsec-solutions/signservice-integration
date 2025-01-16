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
package se.idsec.signservice.integration.document.impl;

import jakarta.annotation.Nonnull;
import lombok.Setter;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import se.idsec.signservice.integration.SignRequestInput;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.config.impl.DefaultIntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.DocumentCache;
import se.idsec.signservice.integration.core.error.InputValidationException;
import se.idsec.signservice.integration.core.error.NoAccessException;
import se.idsec.signservice.integration.core.impl.InMemoryDocumentCache;
import se.idsec.signservice.integration.document.DocumentDecoder;
import se.idsec.signservice.integration.document.DocumentEncoder;
import se.idsec.signservice.integration.document.DocumentProcessingException;
import se.idsec.signservice.integration.document.ProcessedTbsDocument;
import se.idsec.signservice.integration.document.TbsDocument;
import se.idsec.signservice.integration.document.TbsDocument.AdesType;
import se.idsec.signservice.integration.document.TbsDocument.EtsiAdesRequirement;
import se.idsec.signservice.integration.testbase.TestBase;
import se.idsec.signservice.integration.testbase.TestDocumentEncoderDecoder;
import se.idsec.signservice.integration.testbase.TestDocumentType;
import se.idsec.signservice.integration.testbase.TestEtsiAdesRequirementValidator;
import se.swedenconnect.schemas.csig.dssext_1_1.SignTaskData;

import java.util.UUID;

/**
 * Test cases for {@code AbstractTbsDocumentProcessor}.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class AbstractTbsDocumentProcessorTest extends TestBase {

  private final DocumentCache documentCache = new InMemoryDocumentCache();

  private final IntegrationServiceConfiguration config =
      DefaultIntegrationServiceConfiguration.builder().stateless(false).build();

  @Test
  public void testPreProcess() throws Exception {

    final TbsDocument tbsDocument = TbsDocument.builder()
        .id("123")
        .content("DOCUMENT")
        .mimeType("TEST")
        .adesRequirement(EtsiAdesRequirement.builder().adesFormat(AdesType.BES).build())
        .build();

    final TestTbsDocumentProcessor processor = new TestTbsDocumentProcessor();
    processor.afterPropertiesSet();
    final ProcessedTbsDocument pd = processor.preProcess(tbsDocument, null, this.config, this.documentCache, null, "tbs");

    Assertions.assertEquals("123", pd.getTbsDocument().getId());
    Assertions.assertEquals("DOCUMENT", pd.getTbsDocument().getContent());
    Assertions.assertNotNull(pd.getTbsDocument().getAdesRequirement());
    Assertions.assertTrue(pd.getDocumentObject() instanceof TestDocumentType);
    Assertions.assertEquals("DOCUMENT", pd.getDocumentObject(TestDocumentType.class).getContents());
  }

  @Test
  public void testPreProcessCached() throws Exception {

    final String documentContents = "DOCUMENT";
    final String docRef = UUID.randomUUID().toString();

    this.documentCache.put(docRef, documentContents, "the-requester");

    final TbsDocument tbsDocument = TbsDocument.builder()
        .id("123")
        .contentReference(docRef)
        .mimeType("TEST")
        .adesRequirement(EtsiAdesRequirement.builder().adesFormat(AdesType.BES).build())
        .build();

    final TestTbsDocumentProcessor processor = new TestTbsDocumentProcessor();
    processor.afterPropertiesSet();
    final SignRequestInput sri = new SignRequestInput();
    final ProcessedTbsDocument pd =
        processor.preProcess(tbsDocument, sri, this.config, this.documentCache, "the-requester", "tbs");

    Assertions.assertEquals("123", pd.getTbsDocument().getId());
    Assertions.assertEquals(documentContents, pd.getTbsDocument().getContent());
    Assertions.assertNotNull(pd.getTbsDocument().getAdesRequirement());
    Assertions.assertTrue(pd.getDocumentObject() instanceof TestDocumentType);
    Assertions.assertEquals("DOCUMENT", pd.getDocumentObject(TestDocumentType.class).getContents());

    Assertions.assertNull(this.documentCache.get(docRef, null));
  }

  @Test
  public void testPreProcessCachedNoOwner() throws Exception {

    final String documentContents = "DOCUMENT";
    final String docRef = UUID.randomUUID().toString();

    this.documentCache.put(docRef, documentContents, null);

    final TbsDocument tbsDocument = TbsDocument.builder()
        .id("123")
        .contentReference(docRef)
        .mimeType("TEST")
        .adesRequirement(EtsiAdesRequirement.builder().adesFormat(AdesType.BES).build())
        .build();

    final TestTbsDocumentProcessor processor = new TestTbsDocumentProcessor();
    processor.afterPropertiesSet();
    final ProcessedTbsDocument pd =
        processor.preProcess(tbsDocument, new SignRequestInput(), this.config, this.documentCache, null, "tbs");

    Assertions.assertEquals("123", pd.getTbsDocument().getId());
    Assertions.assertEquals(documentContents, pd.getTbsDocument().getContent());
    Assertions.assertNotNull(pd.getTbsDocument().getAdesRequirement());
    Assertions.assertTrue(pd.getDocumentObject() instanceof TestDocumentType);
    Assertions.assertEquals("DOCUMENT", pd.getDocumentObject(TestDocumentType.class).getContents());

    Assertions.assertNull(this.documentCache.get(docRef, null));
  }

  @Test
  public void testPreProcessCachedOtherOwner() throws Exception {

    final String documentContents = "DOCUMENT";
    final String docRef = UUID.randomUUID().toString();

    this.documentCache.put(docRef, documentContents, "the-owner");

    final TbsDocument tbsDocument = TbsDocument.builder()
        .id("123")
        .contentReference(docRef)
        .mimeType("TEST")
        .adesRequirement(EtsiAdesRequirement.builder().adesFormat(AdesType.BES).build())
        .build();

    final TestTbsDocumentProcessor processor = new TestTbsDocumentProcessor();
    processor.afterPropertiesSet();
    final SignRequestInput sri = new SignRequestInput();

    try {
      processor.preProcess(tbsDocument, sri, this.config, this.documentCache, "the-requester", "tbs");
      Assertions.fail("Expected InputValidationException");
    }
    catch (final InputValidationException e) {
      Assertions.assertEquals("tbs.contentReference", e.getObjectName());
      Assertions.assertTrue(e.getCause() instanceof NoAccessException);
    }
    // Make sure that the document is not removed from the cache ...
    Assertions.assertNotNull(this.documentCache.get(docRef, "the-owner"));
  }

  @Test
  public void testPreProcessCachedNoRequester() throws Exception {

    final String documentContents = "DOCUMENT";
    final String docRef = UUID.randomUUID().toString();

    this.documentCache.put(docRef, documentContents, "the-owner");

    final TbsDocument tbsDocument = TbsDocument.builder()
        .id("123")
        .contentReference(docRef)
        .mimeType("TEST")
        .adesRequirement(EtsiAdesRequirement.builder().adesFormat(AdesType.BES).build())
        .build();

    final TestTbsDocumentProcessor processor = new TestTbsDocumentProcessor();
    processor.afterPropertiesSet();
    final SignRequestInput sri = SignRequestInput.builder().build();

    try {
      processor.preProcess(tbsDocument, sri, this.config, this.documentCache, null, "tbs");
      Assertions.fail("Expected InputValidationException");
    }
    catch (final InputValidationException e) {
      Assertions.assertEquals("tbs.contentReference", e.getObjectName());
      Assertions.assertTrue(e.getCause() instanceof NoAccessException);
    }
    // Make sure that the document is not removed from the cache ...
    Assertions.assertNotNull(this.documentCache.get(docRef, "the-owner"));
  }

  @Test
  public void testPreProcessCachedNotFound() throws Exception {

    final TbsDocument tbsDocument = TbsDocument.builder()
        .id("123")
        .contentReference(UUID.randomUUID().toString())
        .mimeType("TEST")
        .adesRequirement(EtsiAdesRequirement.builder().adesFormat(AdesType.BES).build())
        .build();

    final TestTbsDocumentProcessor processor = new TestTbsDocumentProcessor();
    processor.afterPropertiesSet();
    try {
      processor.preProcess(tbsDocument, new SignRequestInput(), this.config, this.documentCache, null, "tbs");
      Assertions.fail("Expected InputValidationException");
    }
    catch (final InputValidationException e) {
      Assertions.assertEquals("tbs.contentReference", e.getObjectName());
    }
  }

  @Test
  public void testPreProcessCachedBothSet() throws Exception {

    final TbsDocument tbsDocument = TbsDocument.builder()
        .id("123")
        .content("DOCUMENT")
        .contentReference(UUID.randomUUID().toString())
        .mimeType("TEST")
        .adesRequirement(EtsiAdesRequirement.builder().adesFormat(AdesType.BES).build())
        .build();

    final TestTbsDocumentProcessor processor = new TestTbsDocumentProcessor();
    processor.afterPropertiesSet();
    Assertions.assertThrows(InputValidationException.class, () -> {
      processor.preProcess(tbsDocument, null, this.config, this.documentCache, null, "tbs");
    });
  }

  @Test
  public void testPreProcessCachedStateless() throws Exception {

    final IntegrationServiceConfiguration stateLessConfig =
        DefaultIntegrationServiceConfiguration.builder().stateless(true).build();

    final TbsDocument tbsDocument = TbsDocument.builder()
        .id("123")
        .contentReference(UUID.randomUUID().toString())
        .mimeType("TEST")
        .adesRequirement(EtsiAdesRequirement.builder().adesFormat(AdesType.BES).build())
        .build();

    final TestTbsDocumentProcessor processor = new TestTbsDocumentProcessor();
    processor.afterPropertiesSet();
    Assertions.assertThrows(InputValidationException.class, () -> {
      processor.preProcess(tbsDocument, null, stateLessConfig, this.documentCache, null, "tbs");
    });
  }

  @Test
  public void testPreProcessFailedValidateContent() throws Exception {

    final TbsDocument tbsDocument = TbsDocument.builder()
        .id("123")
        .content("DOCUMENT")
        .mimeType("TEST")
        .adesRequirement(EtsiAdesRequirement.builder().adesFormat(AdesType.BES).build())
        .build();

    final TestTbsDocumentProcessor processor = new TestTbsDocumentProcessor();
    processor.setFailDecode();
    processor.afterPropertiesSet();
    try {
      processor.preProcess(tbsDocument, null, this.config, this.documentCache, null, "tbs");
      Assertions.fail("Expected InputValidationException");
    }
    catch (final InputValidationException e) {
      Assertions.assertEquals("tbs.content", e.getObjectName());
      Assertions.assertTrue(e.getCause() instanceof DocumentProcessingException);
    }
  }

  @Test
  public void testPreProcessAssignID() throws Exception {

    final TbsDocument tbsDocument = TbsDocument.builder()
        .content("DOCUMENT")
        .mimeType("TEST")
        .build();

    final TestTbsDocumentProcessor processor = new TestTbsDocumentProcessor();
    processor.afterPropertiesSet();
    final ProcessedTbsDocument pd = processor.preProcess(tbsDocument, null, this.config, this.documentCache, null, "tbs");

    Assertions.assertNotNull(pd.getTbsDocument().getId());
  }

  @Test
  public void testPreProcessResetAdesReq() throws Exception {

    final TbsDocument tbsDocument = TbsDocument.builder()
        .id("123")
        .content("DOCUMENT")
        .mimeType("TEST")
        .adesRequirement(new EtsiAdesRequirement())
        .build();

    final TestTbsDocumentProcessor processor = new TestTbsDocumentProcessor();
    processor.afterPropertiesSet();
    final ProcessedTbsDocument pd = processor.preProcess(tbsDocument, null, this.config, this.documentCache, null, "tbs");
    Assertions.assertNull(pd.getTbsDocument().getAdesRequirement());
  }

  // Makes sure that a TbsDocumentValidator is created even if we forget afterPropertiesSet
  @Test
  public void testAutoCreateValidator() throws Exception {
    final TestTbsDocumentProcessor processor = new TestTbsDocumentProcessor();
    final ProcessedTbsDocument pd = processor.preProcess(TbsDocument.builder()
        .id("123").content("DOCUMENT").mimeType("TEST").build(), null, this.config, this.documentCache, null, "tbs");
    Assertions.assertNotNull(pd);
  }

  @Test
  public void testProcess() throws Exception {
    final TbsDocument tbsDocument = TbsDocument.builder()
        .id("123")
        .content("DOCUMENT")
        .mimeType("TEST")
        .build();

    final TestTbsDocumentProcessor processor = new TestTbsDocumentProcessor();
    processor.afterPropertiesSet();
    final ProcessedTbsDocument pd = processor.preProcess(tbsDocument, null, this.config, this.documentCache, null, "tbs");

    final SignTaskData std = processor.process(pd, "dummy", null);
    Assertions.assertArrayEquals("DOCUMENT".getBytes(), std.getToBeSignedBytes());
    Assertions.assertEquals("TEST", std.getSigType());
    Assertions.assertEquals("123", std.getSignTaskId());
    Assertions.assertEquals("None", std.getAdESType());

    Assertions.assertNull(std.getAdESObject());
    Assertions.assertNull(std.getProcessingRules());
    Assertions.assertNull(std.getBase64Signature());
    Assertions.assertNull(std.getOtherSignTaskData());
  }

  @Test
  public void testProcessAdes1() throws Exception {
    final TbsDocument tbsDocument = TbsDocument.builder()
        .id("123")
        .content("DOCUMENT")
        .mimeType("TEST")
        .adesRequirement(EtsiAdesRequirement.builder()
            .adesFormat(AdesType.BES)
            .build())
        .build();

    final TestTbsDocumentProcessor processor = new TestTbsDocumentProcessor();
    processor.setAdesSignatureId("ID");
    processor.afterPropertiesSet();
    final ProcessedTbsDocument pd = processor.preProcess(tbsDocument, null, this.config, this.documentCache, null, "tbs");

    final SignTaskData std = processor.process(pd, "dummy", null);
    Assertions.assertArrayEquals("DOCUMENT".getBytes(), std.getToBeSignedBytes());
    Assertions.assertEquals("TEST", std.getSigType());
    Assertions.assertEquals("123", std.getSignTaskId());
    Assertions.assertEquals("BES", std.getAdESType());
    Assertions.assertEquals("ID", std.getAdESObject().getSignatureId());

    Assertions.assertNull(std.getProcessingRules());
    Assertions.assertNull(std.getBase64Signature());
    Assertions.assertNull(std.getOtherSignTaskData());
  }

  @Test
  public void testProcessAdes2() throws Exception {
    final TbsDocument tbsDocument = TbsDocument.builder()
        .id("123")
        .content("DOCUMENT")
        .mimeType("TEST")
        .adesRequirement(EtsiAdesRequirement.builder()
            .adesFormat(AdesType.BES)
            .build())
        .build();

    final TestTbsDocumentProcessor processor = new TestTbsDocumentProcessor();
    processor.setAdesSignatureId(null);
    processor.afterPropertiesSet();
    final ProcessedTbsDocument pd = processor.preProcess(tbsDocument, null, this.config, this.documentCache, null, "tbs");

    final SignTaskData std = processor.process(pd, "dummy", null);
    Assertions.assertArrayEquals("DOCUMENT".getBytes(), std.getToBeSignedBytes());
    Assertions.assertEquals("TEST", std.getSigType());
    Assertions.assertEquals("123", std.getSignTaskId());
    Assertions.assertEquals("BES", std.getAdESType());

    Assertions.assertNull(std.getAdESObject());
    Assertions.assertNull(std.getProcessingRules());
    Assertions.assertNull(std.getBase64Signature());
    Assertions.assertNull(std.getOtherSignTaskData());
  }

  @Test
  public void testProcessAdes3() throws Exception {
    final TbsDocument tbsDocument = TbsDocument.builder()
        .id("123")
        .content("DOCUMENT")
        .mimeType("TEST")
        .adesRequirement(EtsiAdesRequirement.builder()
            .adesFormat(AdesType.EPES)
            .adesObject("adesobject")
            .build())
        .build();

    final TestTbsDocumentProcessor processor = new TestTbsDocumentProcessor();
    processor.setAdesSignatureId("ID");
    processor.afterPropertiesSet();
    final ProcessedTbsDocument pd = processor.preProcess(tbsDocument, null, this.config, this.documentCache, null, "tbs");

    final SignTaskData std = processor.process(pd, "dummy", null);
    Assertions.assertArrayEquals("DOCUMENT".getBytes(), std.getToBeSignedBytes());
    Assertions.assertEquals("TEST", std.getSigType());
    Assertions.assertEquals("123", std.getSignTaskId());
    Assertions.assertEquals("EPES", std.getAdESType());
    Assertions.assertEquals("ID", std.getAdESObject().getSignatureId());
    Assertions.assertArrayEquals("adesobject".getBytes(), std.getAdESObject().getAdESObjectBytes());

    Assertions.assertNull(std.getProcessingRules());
    Assertions.assertNull(std.getBase64Signature());
    Assertions.assertNull(std.getOtherSignTaskData());
  }

  @Test
  public void testProcessAdes4() throws Exception {
    final TbsDocument tbsDocument = TbsDocument.builder()
        .id("123")
        .content("DOCUMENT")
        .mimeType("TEST")
        .adesRequirement(EtsiAdesRequirement.builder()
            .adesFormat(AdesType.EPES)
            .adesObject("adesobject")
            .signaturePolicy("policy")
            .build())
        .build();

    final TestTbsDocumentProcessor processor = new TestTbsDocumentProcessor();
    processor.setAdesSignatureId("ID");
    processor.afterPropertiesSet();
    final ProcessedTbsDocument pd = processor.preProcess(tbsDocument, null, this.config, this.documentCache, null, "tbs");

    final SignTaskData std = processor.process(pd, "dummy", null);
    Assertions.assertArrayEquals("DOCUMENT".getBytes(), std.getToBeSignedBytes());
    Assertions.assertEquals("TEST", std.getSigType());
    Assertions.assertEquals("123", std.getSignTaskId());
    Assertions.assertEquals("EPES", std.getAdESType());
    Assertions.assertEquals("ID", std.getAdESObject().getSignatureId());
    Assertions.assertArrayEquals("adesobject".getBytes(), std.getAdESObject().getAdESObjectBytes());
    Assertions.assertEquals("policy", std.getProcessingRules());

    Assertions.assertNull(std.getBase64Signature());
    Assertions.assertNull(std.getOtherSignTaskData());
  }

  public static class TestTbsDocumentProcessor extends AbstractTbsDocumentProcessor<TestDocumentType> {

    private final TestDocumentEncoderDecoder encoderDecoder = new TestDocumentEncoderDecoder();

    @Setter
    private String adesSignatureId;

    private final EtsiAdesRequirementValidator etsi = new TestEtsiAdesRequirementValidator();

    public TestTbsDocumentProcessor() {
      super();
    }

    public void setFailDecode() {
      this.encoderDecoder.setFailDecode(true);
    }

    @Override
    public boolean supports(@Nonnull final TbsDocument document) {
      return "TEST".equals(document.getMimeType());
    }

    @Override
    public DocumentDecoder<TestDocumentType> getDocumentDecoder() {
      return this.encoderDecoder;
    }

    @Override
    public DocumentEncoder<TestDocumentType> getDocumentEncoder() {
      return this.encoderDecoder;
    }

    @Override
    protected TbsCalculationResult calculateToBeSigned(final ProcessedTbsDocument document, final String signatureAlgorithm,
        final IntegrationServiceConfiguration config) throws DocumentProcessingException {

      final TbsCalculationResult.TbsCalculationResultBuilder builder = TbsCalculationResult.builder()
          .sigType("TEST")
          .toBeSignedBytes(document.getDocumentObject(TestDocumentType.class).getContents().getBytes());

      if (document.getTbsDocument().getAdesRequirement() != null) {
        if (this.adesSignatureId != null) {
          builder.adesSignatureId(this.adesSignatureId);
        }
        if (document.getTbsDocument().getAdesRequirement().getAdesObject() != null) {
          builder.adesObjectBytes(document.getTbsDocument().getAdesRequirement().getAdesObject().getBytes());
        }
      }
      return builder.build();
    }

    @Override
    protected EtsiAdesRequirementValidator getEtsiAdesRequirementValidator() {
      return this.etsi;
    }

  }
}
