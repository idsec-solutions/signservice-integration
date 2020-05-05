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

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.springframework.core.io.ClassPathResource;

import se.idsec.signservice.integration.SignResponseProcessingParameters;
import se.idsec.signservice.integration.core.error.SignServiceIntegrationException;
import se.idsec.signservice.integration.core.error.impl.InternalSignServiceIntegrationException;
import se.idsec.signservice.integration.document.CompiledSignedDocument;
import se.idsec.signservice.integration.document.DocumentDecoder;
import se.idsec.signservice.integration.document.DocumentEncoder;
import se.idsec.signservice.integration.document.DocumentProcessingException;
import se.idsec.signservice.integration.document.TbsDocument;
import se.idsec.signservice.integration.document.ades.AdesSigningCertificateDigest;
import se.idsec.signservice.integration.dss.SignRequestWrapper;
import se.idsec.signservice.integration.dss.SignResponseWrapper;
import se.idsec.signservice.integration.process.SignResponseProcessingConfig;
import se.idsec.signservice.integration.testbase.TestAdesObject;
import se.idsec.signservice.integration.testbase.TestBase;
import se.idsec.signservice.integration.testbase.TestDocumentEncoderDecoder;
import se.idsec.signservice.integration.testbase.TestDocumentType;
import se.idsec.signservice.security.certificate.CertificateUtils;
import se.swedenconnect.schemas.csig.dssext_1_1.SignTaskData;

/**
 * Test cases for {@code AbstractSignedDocumentProcessor}.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class AbstractSignedDocumentProcessorTest extends TestBase {

  private static se.swedenconnect.schemas.csig.dssext_1_1.ObjectFactory dssExtFactory =
      new se.swedenconnect.schemas.csig.dssext_1_1.ObjectFactory();

  private X509Certificate cert;

  public AbstractSignedDocumentProcessorTest() throws CertificateException, IOException {
    this.cert = CertificateUtils.decodeCertificate(
      (new ClassPathResource("idsec.se.cer")).getInputStream());
  }

  @Test
  public void testCorrectDigest() throws Exception {
    final byte[] certEncoding = this.cert.getEncoded();
    final byte[] digest = digest("SHA-256", certEncoding);

    final AdesSigningCertificateDigest adesCD = AdesSigningCertificateDigest.builder()
      .digestValue(digest)
      .digestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256)
      .build();
    final TestAdesObject adesObject = new TestAdesObject(adesCD);

    SignTaskData signTaskData = dssExtFactory.createSignTaskData();
    signTaskData.setSignTaskId("STID-1");

    SignRequestWrapper signRequest = new SignRequestWrapper();
    signRequest.setRequestID("REQID-1");

    SignedDocumentProcessor processor = new SignedDocumentProcessor();
    processor.afterPropertiesSet();
    processor.validateAdesObject(adesObject, this.cert, signTaskData, signRequest, new SignResponseWrapper(),
      new SignResponseProcessingParameters());
  }

  @Test
  public void testIncorrectDigest() throws Exception {
    final byte[] certEncoding = this.cert.getEncoded();
    final byte[] digest = digest("SHA-256", certEncoding);
    digest[0] = (byte) ~digest[0];

    final AdesSigningCertificateDigest adesCD = AdesSigningCertificateDigest.builder()
      .digestValue(digest)
      .digestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256)
      .build();
    final TestAdesObject adesObject = new TestAdesObject(adesCD);

    SignTaskData signTaskData = dssExtFactory.createSignTaskData();
    signTaskData.setSignTaskId("STID-1");

    SignRequestWrapper signRequest = new SignRequestWrapper();
    signRequest.setRequestID("REQID-1");

    SignedDocumentProcessor processor = new SignedDocumentProcessor();
    processor.afterPropertiesSet();
    try {
      processor.validateAdesObject(adesObject, this.cert, signTaskData, signRequest, new SignResponseWrapper(),
        new SignResponseProcessingParameters());
      Assert.fail("Expected DocumentProcessingException");
    }
    catch (DocumentProcessingException e) {
    }
  }

  @Test
  public void testUnsupportedAlgorithm() throws Exception {
    final byte[] certEncoding = this.cert.getEncoded();
    final byte[] digest = digest("SHA-256", certEncoding);

    final AdesSigningCertificateDigest adesCD = AdesSigningCertificateDigest.builder()
      .digestValue(digest)
      .digestMethod("http://not.a.real.algo")
      .build();
    final TestAdesObject adesObject = new TestAdesObject(adesCD);

    SignTaskData signTaskData = dssExtFactory.createSignTaskData();
    signTaskData.setSignTaskId("STID-1");

    SignRequestWrapper signRequest = new SignRequestWrapper();
    signRequest.setRequestID("REQID-1");

    SignedDocumentProcessor processor = new SignedDocumentProcessor();
    processor.afterPropertiesSet();
    try {
      processor.validateAdesObject(adesObject, this.cert, signTaskData, signRequest, new SignResponseWrapper(),
        new SignResponseProcessingParameters());
      Assert.fail("Expected InternalSignServiceIntegrationException");
    }
    catch (InternalSignServiceIntegrationException e) {
    }
  }

  @Test
  public void testMissignDigest() throws Exception {
    final TestAdesObject adesObject = new TestAdesObject(null);

    SignTaskData signTaskData = dssExtFactory.createSignTaskData();
    signTaskData.setSignTaskId("STID-1");

    SignRequestWrapper signRequest = new SignRequestWrapper();
    signRequest.setRequestID("REQID-1");

    SignedDocumentProcessor processor = new SignedDocumentProcessor();
    processor.afterPropertiesSet();
    try {
      processor.validateAdesObject(adesObject, this.cert, signTaskData, signRequest, new SignResponseWrapper(),
        new SignResponseProcessingParameters());
      Assert.fail("Expected DocumentProcessingException");
    }
    catch (DocumentProcessingException e) {
    }
  }

  @Test
  public void testInit() throws Exception {
    SignedDocumentProcessor processor = new SignedDocumentProcessor();
    processor.afterPropertiesSet();
    Assert.assertNotNull(processor.getProcessingConfiguration());
  }

  @Test
  public void testSetProcessingConfig() throws Exception {
    SignResponseProcessingConfig ownConfig = new SignResponseProcessingConfig();
    ownConfig.setMaximumAllowedProcessingTime(100L);

    SignedDocumentProcessor processor = new SignedDocumentProcessor();
    processor.setProcessingConfiguration(ownConfig);
    processor.afterPropertiesSet();

    Assert.assertEquals(100L, processor.getProcessingConfiguration().getMaximumAllowedProcessingTime());

    // Assert that null is ignored
    processor.setProcessingConfiguration(null);
    Assert.assertEquals(100L, processor.getProcessingConfiguration().getMaximumAllowedProcessingTime());
  }

  @Test
  public void testHelpfulGetProcessingConfig() throws Exception {
    SignedDocumentProcessor processor = new SignedDocumentProcessor();
    // No after properties set is called

    // Assert that get creates a default config if null
    Assert.assertNotNull(processor.getProcessingConfiguration());
  }

  private static byte[] digest(final String jcaAlgorithm, final byte[] data) throws NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance(jcaAlgorithm);
    return digest.digest(data);
  }

  public static class SignedDocumentProcessor extends AbstractSignedDocumentProcessor<TestDocumentType, TestAdesObject> {

    private TestDocumentEncoderDecoder encoderDecoder = new TestDocumentEncoderDecoder();

    @Override
    public boolean supports(SignTaskData signData) {
      return "TEST".equalsIgnoreCase(signData.getSigType());
    }

    @Override
    public CompiledSignedDocument<TestDocumentType, TestAdesObject>
        buildSignedDocument(TbsDocument tbsDocument, SignTaskData signedData,
            List<X509Certificate> signerCertificateChain, SignRequestWrapper signRequest, SignResponseProcessingParameters parameters)
            throws SignServiceIntegrationException {

      return null;
    }

    @Override
    public void validateSignedDocument(TestDocumentType signedDocument, X509Certificate signerCertificate, SignTaskData signTaskData,
        SignResponseProcessingParameters parameters, String requestID) throws SignServiceIntegrationException {
    }

    @Override
    public DocumentDecoder<TestDocumentType> getDocumentDecoder() {
      return this.encoderDecoder;
    }

    @Override
    public DocumentEncoder<TestDocumentType> getDocumentEncoder() {
      return this.encoderDecoder;
    }

  }

}
