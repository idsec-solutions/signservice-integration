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
import jakarta.annotation.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import se.idsec.signservice.integration.SignResponseProcessingParameters;
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

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;

/**
 * Test cases for {@code AbstractSignedDocumentProcessor}.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class AbstractSignedDocumentProcessorTest extends TestBase {

  private static final se.swedenconnect.schemas.csig.dssext_1_1.ObjectFactory dssExtFactory =
      new se.swedenconnect.schemas.csig.dssext_1_1.ObjectFactory();

  private final X509Certificate cert;

  public AbstractSignedDocumentProcessorTest() throws CertificateException, IOException {
    try (final InputStream is = this.getClass().getClassLoader().getResourceAsStream("idsec.se.cer")) {
      this.cert = CertificateUtils.decodeCertificate(is);
    }
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

    final SignTaskData signTaskData = dssExtFactory.createSignTaskData();
    signTaskData.setSignTaskId("STID-1");

    final SignRequestWrapper signRequest = new SignRequestWrapper();
    signRequest.setRequestID("REQID-1");

    final SignedDocumentProcessor processor = new SignedDocumentProcessor();
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

    final SignTaskData signTaskData = dssExtFactory.createSignTaskData();
    signTaskData.setSignTaskId("STID-1");

    final SignRequestWrapper signRequest = new SignRequestWrapper();
    signRequest.setRequestID("REQID-1");

    final SignedDocumentProcessor processor = new SignedDocumentProcessor();
    processor.afterPropertiesSet();
    Assertions.assertThrows(DocumentProcessingException.class, () ->
        processor.validateAdesObject(adesObject, this.cert, signTaskData, signRequest, new SignResponseWrapper(),
            new SignResponseProcessingParameters()));
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

    final SignTaskData signTaskData = dssExtFactory.createSignTaskData();
    signTaskData.setSignTaskId("STID-1");

    final SignRequestWrapper signRequest = new SignRequestWrapper();
    signRequest.setRequestID("REQID-1");

    final SignedDocumentProcessor processor = new SignedDocumentProcessor();
    processor.afterPropertiesSet();
    Assertions.assertThrows(InternalSignServiceIntegrationException.class, () ->
        processor.validateAdesObject(adesObject, this.cert, signTaskData, signRequest, new SignResponseWrapper(),
            new SignResponseProcessingParameters()));
  }

  @Test
  public void testMissignDigest() throws Exception {
    final TestAdesObject adesObject = new TestAdesObject(null);

    final SignTaskData signTaskData = dssExtFactory.createSignTaskData();
    signTaskData.setSignTaskId("STID-1");

    final SignRequestWrapper signRequest = new SignRequestWrapper();
    signRequest.setRequestID("REQID-1");

    final SignedDocumentProcessor processor = new SignedDocumentProcessor();
    processor.afterPropertiesSet();
    Assertions.assertThrows(DocumentProcessingException.class, () ->
        processor.validateAdesObject(adesObject, this.cert, signTaskData, signRequest, new SignResponseWrapper(),
            new SignResponseProcessingParameters()));
  }

  @Test
  public void testInit() throws Exception {
    final SignedDocumentProcessor processor = new SignedDocumentProcessor();
    processor.afterPropertiesSet();
    Assertions.assertNotNull(processor.getProcessingConfiguration());
  }

  @Test
  public void testSetProcessingConfig() throws Exception {
    final SignResponseProcessingConfig ownConfig = new SignResponseProcessingConfig();
    ownConfig.setMaximumAllowedProcessingTimeDuration(Duration.ofMillis(100L));

    final SignedDocumentProcessor processor = new SignedDocumentProcessor();
    processor.setProcessingConfiguration(ownConfig);
    processor.afterPropertiesSet();

    Assertions.assertEquals(100L,
        processor.getProcessingConfiguration().getMaximumAllowedProcessingTimeDuration().toMillis());

    // Assert that null is ignored
    processor.setProcessingConfiguration(null);
    Assertions.assertEquals(100L,
        processor.getProcessingConfiguration().getMaximumAllowedProcessingTimeDuration().toMillis());
  }

  @Test
  public void testHelpfulGetProcessingConfig() {
    final SignedDocumentProcessor processor = new SignedDocumentProcessor();
    // After properties set is not called

    // Assert that get creates a default config if null
    Assertions.assertNotNull(processor.getProcessingConfiguration());
  }

  private static byte[] digest(final String jcaAlgorithm, final byte[] data) throws NoSuchAlgorithmException {
    final MessageDigest digest = MessageDigest.getInstance(jcaAlgorithm);
    return digest.digest(data);
  }

  public static class SignedDocumentProcessor
      extends AbstractSignedDocumentProcessor<TestDocumentType, TestAdesObject> {

    private final TestDocumentEncoderDecoder encoderDecoder = new TestDocumentEncoderDecoder();

    @Override
    public boolean supports(@Nonnull final SignTaskData signData) {
      return "TEST".equalsIgnoreCase(signData.getSigType());
    }

    @Override
    public CompiledSignedDocument<TestDocumentType, TestAdesObject>
    buildSignedDocument(@Nonnull final TbsDocument tbsDocument, @Nonnull final SignTaskData signedData,
        @Nonnull final List<X509Certificate> signerCertificateChain, @Nonnull final SignRequestWrapper signRequest,
        final SignResponseProcessingParameters parameters) {

      return null;
    }

    @Override
    public void validateSignedDocument(@Nonnull final TestDocumentType signedDocument,
        @Nonnull final X509Certificate signerCertificate, @Nonnull final SignTaskData signTaskData,
        @Nullable final SignResponseProcessingParameters parameters, @Nonnull final String requestID) {
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
