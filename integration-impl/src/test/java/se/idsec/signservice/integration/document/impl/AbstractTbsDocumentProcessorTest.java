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
package se.idsec.signservice.integration.document.impl;

import java.util.UUID;

import org.junit.Assert;
import org.junit.Test;

import lombok.Setter;
import se.idsec.signservice.integration.SignRequestInput;
import se.idsec.signservice.integration.SignServiceIntegrationService;
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

/**
 * Test cases for {@code AbstractTbsDocumentProcessor}.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class AbstractTbsDocumentProcessorTest extends TestBase {
  
  private final DocumentCache documentCache = new InMemoryDocumentCache();
  
  private final IntegrationServiceConfiguration config = DefaultIntegrationServiceConfiguration.builder().stateless(false).build();
  
  @Test
  public void testPreProcess() throws Exception {
    
    TbsDocument tbsDocument = TbsDocument.builder()
        .id("123")
        .content("DOCUMENT")
        .mimeType("TEST")
        .adesRequirement(EtsiAdesRequirement.builder().adesFormat(AdesType.BES).build())
        .build();
    
    TestTbsDocumentProcessor processor = new TestTbsDocumentProcessor();
    processor.afterPropertiesSet();    
    ProcessedTbsDocument pd = processor.preProcess(tbsDocument, null, config, this.documentCache, "tbs");
    
    Assert.assertEquals("123", pd.getTbsDocument().getId());
    Assert.assertEquals("DOCUMENT", pd.getTbsDocument().getContent());
    Assert.assertNotNull(pd.getTbsDocument().getAdesRequirement());
    Assert.assertTrue(TestDocumentType.class.isInstance(pd.getDocumentObject()));
    Assert.assertEquals("DOCUMENT", pd.getDocumentObject(TestDocumentType.class).getContents());    
  }
  
  @Test
  public void testPreProcessCached() throws Exception {
    
    final String documentContents = "DOCUMENT";
    final String docRef = UUID.randomUUID().toString();
    
    this.documentCache.put(docRef, documentContents, "the-requester");
    
    TbsDocument tbsDocument = TbsDocument.builder()
        .id("123")
        .contentReference(docRef)
        .mimeType("TEST")
        .adesRequirement(EtsiAdesRequirement.builder().adesFormat(AdesType.BES).build())
        .build();
    
    TestTbsDocumentProcessor processor = new TestTbsDocumentProcessor();
    processor.afterPropertiesSet();
    SignRequestInput sri = new SignRequestInput();
    sri.addExtensionValue(SignServiceIntegrationService.OWNER_ID_EXTENSION_KEY, "the-requester");
    ProcessedTbsDocument pd = processor.preProcess(tbsDocument, sri, this.config, this.documentCache, "tbs");
    
    Assert.assertEquals("123", pd.getTbsDocument().getId());
    Assert.assertEquals(documentContents, pd.getTbsDocument().getContent());
    Assert.assertNotNull(pd.getTbsDocument().getAdesRequirement());
    Assert.assertTrue(TestDocumentType.class.isInstance(pd.getDocumentObject()));
    Assert.assertEquals("DOCUMENT", pd.getDocumentObject(TestDocumentType.class).getContents());
    
    Assert.assertNull(this.documentCache.get(docRef, null));
  }
  
  @Test
  public void testPreProcessCachedNoOwner() throws Exception {
    
    final String documentContents = "DOCUMENT";
    final String docRef = UUID.randomUUID().toString();
    
    this.documentCache.put(docRef, documentContents, null);
    
    TbsDocument tbsDocument = TbsDocument.builder()
        .id("123")
        .contentReference(docRef)
        .mimeType("TEST")
        .adesRequirement(EtsiAdesRequirement.builder().adesFormat(AdesType.BES).build())
        .build();
    
    TestTbsDocumentProcessor processor = new TestTbsDocumentProcessor();
    processor.afterPropertiesSet();
    ProcessedTbsDocument pd = processor.preProcess(tbsDocument, new SignRequestInput(), this.config, this.documentCache, "tbs");
    
    Assert.assertEquals("123", pd.getTbsDocument().getId());
    Assert.assertEquals(documentContents, pd.getTbsDocument().getContent());
    Assert.assertNotNull(pd.getTbsDocument().getAdesRequirement());
    Assert.assertTrue(TestDocumentType.class.isInstance(pd.getDocumentObject()));
    Assert.assertEquals("DOCUMENT", pd.getDocumentObject(TestDocumentType.class).getContents());
    
    Assert.assertNull(this.documentCache.get(docRef, null));
  }
  
  @Test
  public void testPreProcessCachedOtherOwner() throws Exception {
    
    final String documentContents = "DOCUMENT";
    final String docRef = UUID.randomUUID().toString();
    
    this.documentCache.put(docRef, documentContents, "the-owner");
    
    TbsDocument tbsDocument = TbsDocument.builder()
        .id("123")
        .contentReference(docRef)
        .mimeType("TEST")
        .adesRequirement(EtsiAdesRequirement.builder().adesFormat(AdesType.BES).build())
        .build();
    
    TestTbsDocumentProcessor processor = new TestTbsDocumentProcessor();
    processor.afterPropertiesSet();
    SignRequestInput sri = new SignRequestInput();
    sri.addExtensionValue(SignServiceIntegrationService.OWNER_ID_EXTENSION_KEY, "the-requester");
    
    try {
      processor.preProcess(tbsDocument, sri, this.config, this.documentCache, "tbs");
      Assert.fail("Expected InputValidationException");
    }
    catch (InputValidationException e) {
      Assert.assertEquals("tbs.contentReference", e.getObjectName());
      Assert.assertTrue(NoAccessException.class.isInstance(e.getCause()));
    }    
    // Make sure that the document is not removed from the cache ...
    Assert.assertNotNull(this.documentCache.get(docRef, "the-owner"));
  }
  
  @Test
  public void testPreProcessCachedNoRequester() throws Exception {
    
    final String documentContents = "DOCUMENT";
    final String docRef = UUID.randomUUID().toString();
    
    this.documentCache.put(docRef, documentContents, "the-owner");
    
    TbsDocument tbsDocument = TbsDocument.builder()
        .id("123")
        .contentReference(docRef)
        .mimeType("TEST")
        .adesRequirement(EtsiAdesRequirement.builder().adesFormat(AdesType.BES).build())
        .build();
    
    TestTbsDocumentProcessor processor = new TestTbsDocumentProcessor();
    processor.afterPropertiesSet();
    SignRequestInput sri = SignRequestInput.builder().build();
    
    try {
      processor.preProcess(tbsDocument, sri, this.config, this.documentCache, "tbs");
      Assert.fail("Expected InputValidationException");
    }
    catch (InputValidationException e) {
      Assert.assertEquals("tbs.contentReference", e.getObjectName());
      Assert.assertTrue(NoAccessException.class.isInstance(e.getCause()));
    }    
    // Make sure that the document is not removed from the cache ...
    Assert.assertNotNull(this.documentCache.get(docRef, "the-owner"));
  }  
  
  @Test
  public void testPreProcessCachedNotFound() throws Exception {
    
    TbsDocument tbsDocument = TbsDocument.builder()
        .id("123")
        .contentReference(UUID.randomUUID().toString())
        .mimeType("TEST")
        .adesRequirement(EtsiAdesRequirement.builder().adesFormat(AdesType.BES).build())
        .build();
    
    TestTbsDocumentProcessor processor = new TestTbsDocumentProcessor();
    processor.afterPropertiesSet();    
    try {
      processor.preProcess(tbsDocument, new SignRequestInput(), this.config, this.documentCache, "tbs");
      Assert.fail("Expected InputValidationException");
    }
    catch (InputValidationException e) {
      Assert.assertEquals("tbs.contentReference", e.getObjectName());
    }
  }
  
  @Test(expected = InputValidationException.class)
  public void testPreProcessCachedBothSet() throws Exception {
    
    TbsDocument tbsDocument = TbsDocument.builder()
        .id("123")
        .content("DOCUMENT")
        .contentReference(UUID.randomUUID().toString())
        .mimeType("TEST")
        .adesRequirement(EtsiAdesRequirement.builder().adesFormat(AdesType.BES).build())
        .build();
    
    TestTbsDocumentProcessor processor = new TestTbsDocumentProcessor();
    processor.afterPropertiesSet();    
    processor.preProcess(tbsDocument, null, this.config, this.documentCache, "tbs");
  }  
  
  @Test(expected = InputValidationException.class)
  public void testPreProcessCachedStateless() throws Exception {
    
    final IntegrationServiceConfiguration stateLessConfig = 
        DefaultIntegrationServiceConfiguration.builder().stateless(true).build();    
    
    TbsDocument tbsDocument = TbsDocument.builder()
        .id("123")
        .contentReference(UUID.randomUUID().toString())
        .mimeType("TEST")
        .adesRequirement(EtsiAdesRequirement.builder().adesFormat(AdesType.BES).build())
        .build();
    
    TestTbsDocumentProcessor processor = new TestTbsDocumentProcessor();
    processor.afterPropertiesSet();    
    processor.preProcess(tbsDocument, null, stateLessConfig, this.documentCache, "tbs");
  }
  
  @Test
  public void testPreProcessFailedValidateContent() throws Exception {
    
    TbsDocument tbsDocument = TbsDocument.builder()
        .id("123")
        .content("DOCUMENT")
        .mimeType("TEST")
        .adesRequirement(EtsiAdesRequirement.builder().adesFormat(AdesType.BES).build())
        .build();
    
    TestTbsDocumentProcessor processor = new TestTbsDocumentProcessor();
    processor.setFailDecode();
    processor.afterPropertiesSet();    
    try {
      processor.preProcess(tbsDocument, null, this.config, this.documentCache, "tbs");
      Assert.fail("Expected InputValidationException");
    }
    catch (InputValidationException e) {
      Assert.assertEquals("tbs.content", e.getObjectName());
      Assert.assertTrue(DocumentProcessingException.class.isInstance(e.getCause()));
    }
  }
  
  @Test
  public void testPreProcessAssignID() throws Exception {
    
    TbsDocument tbsDocument = TbsDocument.builder()
        .content("DOCUMENT")
        .mimeType("TEST")
        .build();
    
    TestTbsDocumentProcessor processor = new TestTbsDocumentProcessor();
    processor.afterPropertiesSet();    
    ProcessedTbsDocument pd = processor.preProcess(tbsDocument, null, this.config, this.documentCache, "tbs");
    
    Assert.assertNotNull(pd.getTbsDocument().getId());
  }
  
  @Test
  public void testPreProcessResetAdesReq() throws Exception {
    
    TbsDocument tbsDocument = TbsDocument.builder()
        .id("123")
        .content("DOCUMENT")
        .mimeType("TEST")
        .adesRequirement(new EtsiAdesRequirement())
        .build();
    
    TestTbsDocumentProcessor processor = new TestTbsDocumentProcessor();
    processor.afterPropertiesSet();    
    ProcessedTbsDocument pd = processor.preProcess(tbsDocument, null, this.config, this.documentCache, "tbs");
    Assert.assertNull(pd.getTbsDocument().getAdesRequirement());
  }  
  
  // Makes sure that a TbsDocumentValidator is created even if we forget afterPropertiesSet
  @Test
  public void testAutoCreateValidator() throws Exception {
    TestTbsDocumentProcessor processor = new TestTbsDocumentProcessor();
    ProcessedTbsDocument pd = processor.preProcess(TbsDocument.builder()
      .id("123").content("DOCUMENT").mimeType("TEST").build(), null, this.config, this.documentCache, "tbs");
    Assert.assertNotNull(pd);
  }
  
  @Test
  public void testProcess() throws Exception {
    TbsDocument tbsDocument = TbsDocument.builder()
        .id("123")
        .content("DOCUMENT")
        .mimeType("TEST")
        .build();
    
    TestTbsDocumentProcessor processor = new TestTbsDocumentProcessor();
    processor.afterPropertiesSet();    
    ProcessedTbsDocument pd = processor.preProcess(tbsDocument, null, this.config, this.documentCache, "tbs");
    
    SignTaskData std = processor.process(pd, "dummy", null);
    Assert.assertArrayEquals("DOCUMENT".getBytes(), std.getToBeSignedBytes());
    Assert.assertEquals("TEST", std.getSigType());
    Assert.assertEquals("123", std.getSignTaskId());
    Assert.assertEquals("None", std.getAdESType());
    
    Assert.assertNull(std.getAdESObject());
    Assert.assertNull(std.getProcessingRules());
    Assert.assertNull(std.getBase64Signature());
    Assert.assertNull(std.getOtherSignTaskData());
  }
  
  @Test
  public void testProcessAdes1() throws Exception {
    TbsDocument tbsDocument = TbsDocument.builder()
        .id("123")
        .content("DOCUMENT")
        .mimeType("TEST")
        .adesRequirement(EtsiAdesRequirement.builder()
          .adesFormat(AdesType.BES)
          .build())
        .build();
    
    TestTbsDocumentProcessor processor = new TestTbsDocumentProcessor();
    processor.setAdesSignatureId("ID");
    processor.afterPropertiesSet();    
    ProcessedTbsDocument pd = processor.preProcess(tbsDocument, null, this.config, this.documentCache, "tbs");
    
    SignTaskData std = processor.process(pd, "dummy", null);
    Assert.assertArrayEquals("DOCUMENT".getBytes(), std.getToBeSignedBytes());
    Assert.assertEquals("TEST", std.getSigType());
    Assert.assertEquals("123", std.getSignTaskId());
    Assert.assertEquals("BES", std.getAdESType());
    Assert.assertEquals("ID", std.getAdESObject().getSignatureId());
    
    Assert.assertNull(std.getProcessingRules());
    Assert.assertNull(std.getBase64Signature());
    Assert.assertNull(std.getOtherSignTaskData());
  }
  
  @Test
  public void testProcessAdes2() throws Exception {
    TbsDocument tbsDocument = TbsDocument.builder()
        .id("123")
        .content("DOCUMENT")
        .mimeType("TEST")
        .adesRequirement(EtsiAdesRequirement.builder()
          .adesFormat(AdesType.BES)
          .build())
        .build();
    
    TestTbsDocumentProcessor processor = new TestTbsDocumentProcessor();
    processor.setAdesSignatureId(null);
    processor.afterPropertiesSet();    
    ProcessedTbsDocument pd = processor.preProcess(tbsDocument, null, this.config, this.documentCache, "tbs");
    
    SignTaskData std = processor.process(pd, "dummy", null);
    Assert.assertArrayEquals("DOCUMENT".getBytes(), std.getToBeSignedBytes());
    Assert.assertEquals("TEST", std.getSigType());
    Assert.assertEquals("123", std.getSignTaskId());
    Assert.assertEquals("BES", std.getAdESType());
    
    Assert.assertNull(std.getAdESObject());
    Assert.assertNull(std.getProcessingRules());
    Assert.assertNull(std.getBase64Signature());
    Assert.assertNull(std.getOtherSignTaskData());
  }
  
  @Test
  public void testProcessAdes3() throws Exception {
    TbsDocument tbsDocument = TbsDocument.builder()
        .id("123")
        .content("DOCUMENT")
        .mimeType("TEST")
        .adesRequirement(EtsiAdesRequirement.builder()
          .adesFormat(AdesType.EPES)
          .adesObject("adesobject")
          .build())
        .build();
    
    TestTbsDocumentProcessor processor = new TestTbsDocumentProcessor();
    processor.setAdesSignatureId("ID");
    processor.afterPropertiesSet();    
    ProcessedTbsDocument pd = processor.preProcess(tbsDocument, null, this.config, this.documentCache, "tbs");
    
    SignTaskData std = processor.process(pd, "dummy", null);
    Assert.assertArrayEquals("DOCUMENT".getBytes(), std.getToBeSignedBytes());
    Assert.assertEquals("TEST", std.getSigType());
    Assert.assertEquals("123", std.getSignTaskId());
    Assert.assertEquals("EPES", std.getAdESType());
    Assert.assertEquals("ID", std.getAdESObject().getSignatureId());
    Assert.assertArrayEquals("adesobject".getBytes(), std.getAdESObject().getAdESObjectBytes());
    
    Assert.assertNull(std.getProcessingRules());
    Assert.assertNull(std.getBase64Signature());
    Assert.assertNull(std.getOtherSignTaskData());
  }
  
  @Test
  public void testProcessAdes4() throws Exception {
    TbsDocument tbsDocument = TbsDocument.builder()
        .id("123")
        .content("DOCUMENT")
        .mimeType("TEST")
        .adesRequirement(EtsiAdesRequirement.builder()
          .adesFormat(AdesType.EPES)
          .adesObject("adesobject")
          .signaturePolicy("policy")
          .build())
        .build();
    
    TestTbsDocumentProcessor processor = new TestTbsDocumentProcessor();
    processor.setAdesSignatureId("ID");
    processor.afterPropertiesSet();    
    ProcessedTbsDocument pd = processor.preProcess(tbsDocument, null, this.config, this.documentCache, "tbs");
    
    SignTaskData std = processor.process(pd, "dummy", null);
    Assert.assertArrayEquals("DOCUMENT".getBytes(), std.getToBeSignedBytes());
    Assert.assertEquals("TEST", std.getSigType());
    Assert.assertEquals("123", std.getSignTaskId());
    Assert.assertEquals("EPES", std.getAdESType());
    Assert.assertEquals("ID", std.getAdESObject().getSignatureId());
    Assert.assertArrayEquals("adesobject".getBytes(), std.getAdESObject().getAdESObjectBytes());
    Assert.assertEquals("policy", std.getProcessingRules());
    
    Assert.assertNull(std.getBase64Signature());
    Assert.assertNull(std.getOtherSignTaskData());
  }  

  public static class TestTbsDocumentProcessor extends AbstractTbsDocumentProcessor<TestDocumentType> {
    
    private TestDocumentEncoderDecoder encoderDecoder = new TestDocumentEncoderDecoder();
    
    @Setter
    private String adesSignatureId;
    
    private EtsiAdesRequirementValidator etsi = new TestEtsiAdesRequirementValidator();
    
    public TestTbsDocumentProcessor() {
      super();
    }
    
    public void setFailDecode() {
      this.encoderDecoder.setFailDecode(true);
    }

    @Override
    public boolean supports(TbsDocument document) {
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
    protected TbsCalculationResult calculateToBeSigned(ProcessedTbsDocument document, String signatureAlgorithm,
        IntegrationServiceConfiguration config) throws DocumentProcessingException {

      TbsCalculationResult.TbsCalculationResultBuilder builder = TbsCalculationResult.builder()
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
