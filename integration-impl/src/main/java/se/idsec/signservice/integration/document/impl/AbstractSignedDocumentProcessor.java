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
package se.idsec.signservice.integration.document.impl;

import jakarta.annotation.Nonnull;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.SignResponseProcessingParameters;
import se.idsec.signservice.integration.core.error.ErrorCode;
import se.idsec.signservice.integration.core.error.SignServiceIntegrationException;
import se.idsec.signservice.integration.core.error.impl.InternalSignServiceIntegrationException;
import se.idsec.signservice.integration.core.impl.CorrelationID;
import se.idsec.signservice.integration.document.DocumentProcessingException;
import se.idsec.signservice.integration.document.SignedDocumentProcessor;
import se.idsec.signservice.integration.document.ades.AdesObject;
import se.idsec.signservice.integration.document.ades.AdesSigningCertificateDigest;
import se.idsec.signservice.integration.dss.SignRequestWrapper;
import se.idsec.signservice.integration.dss.SignResponseWrapper;
import se.idsec.signservice.integration.process.SignResponseProcessingConfig;
import se.swedenconnect.schemas.csig.dssext_1_1.SignTaskData;
import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.security.algorithms.AlgorithmRegistrySingleton;
import se.swedenconnect.security.algorithms.MessageDigestAlgorithm;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Optional;

/**
 * Abstract base class for {@link SignedDocumentProcessor} implementations.
 *
 * @param <T> the type of signature document
 * @param <X> AdES type
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public abstract class AbstractSignedDocumentProcessor<T, X extends AdesObject>
    implements SignedDocumentProcessor<T, X> {

  /** Processing configuration. */
  private SignResponseProcessingConfig processingConfiguration;

  /** The algorithm registry. */
  private AlgorithmRegistry algorithmRegistry;

  /** {@inheritDoc} */
  @Override
  public final void validateAdesObject(@Nonnull final X adesObject, @Nonnull final X509Certificate signingCertificate,
      @Nonnull final SignTaskData signTaskData,
      @Nonnull final SignRequestWrapper signRequest, @Nonnull final SignResponseWrapper signResponse,
      final SignResponseProcessingParameters parameters) throws SignServiceIntegrationException {

    final AdesSigningCertificateDigest certDigest = adesObject.getSigningCertificateDigest();
    if (certDigest == null) {
      final String msg =
          String.format("No signer certificate digest found in AdES object for sign task '%s' [request-id='%s']",
              signTaskData.getSignTaskId(), signRequest.getRequestID());
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new DocumentProcessingException(new ErrorCode.Code("invalid-ades-object"), msg);
    }

    // Use the algorithm registry to instantiate a digest and then compare the calculated
    // digest with the claimed value.
    //
    final String jcaName = Optional.ofNullable(
            this.getAlgorithmRegistry().getAlgorithm(certDigest.getDigestMethod(), MessageDigestAlgorithm.class))
        .map(MessageDigestAlgorithm::getJcaName)
        .orElse(null);
    if (jcaName == null) {
      final String msg = String.format(
          "While performing AdES validation for sign task '%s' - Can not check digest of signer certificate - Algorithm '%s' is unsupported [request-id='%s']",
          signTaskData.getSignTaskId(), certDigest.getDigestMethod(), signRequest.getRequestID());
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new InternalSignServiceIntegrationException(new ErrorCode.Code("unsupported-algorithm"), msg);
    }
    try {
      final MessageDigest digest = MessageDigest.getInstance(jcaName);
      final byte[] calculatedDigest = digest.digest(signingCertificate.getEncoded());
      if (!Arrays.equals(certDigest.getDigestValue(), calculatedDigest)) {
        final String msg =
            String.format("AdES digest validation of signer certificate failed for sign task '%s' [request-id='%s']",
                signTaskData.getSignTaskId(), signRequest.getRequestID());
        log.error("{}: {}", CorrelationID.id(), msg);
        throw new DocumentProcessingException(new ErrorCode.Code("ades-validation-error"), msg);
      }
      log.debug("{}: Successfully validated certificate digest in AdES object for sign task '{}' '[request-id='{}']",
          CorrelationID.id(), signTaskData.getSignTaskId(), signRequest.getRequestID());
    }
    catch (final NoSuchAlgorithmException | CertificateEncodingException e) {
      // Should not happen (otherwise the getAlgorithmID would have failed, or certificate would have been rejected).
      log.error("{}: {}", CorrelationID.id(), e.getMessage(), e);
      throw new SecurityException(e);
    }

    // Make additional checks ...
    //
    this.performAdditionalAdesValidation(adesObject, signingCertificate, signTaskData, signRequest, signResponse,
        parameters);
  }

  /**
   * The
   * {@link #validateAdesObject(AdesObject, X509Certificate, SignTaskData, SignRequestWrapper, SignResponseWrapper,
   * SignResponseProcessingParameters)} method validates that the signer certificate digest of the AdES object is valid.
   * Implementations wishing to check other aspects of the AdES object should implement this method. The default
   * implemention does nothing.
   * <p>
   * Validaton errors should use the error code "ades-validation-error", e.g.
   * {@code throw new DocumentProcessingException(new ErrorCode.Code("ades-validation-error"), msg)}.
   * </p>
   *
   * @param adesObject the AdES object
   * @param signingCertificate the signing certificate
   * @param signTaskData the sign data
   * @param signRequest the sign request
   * @param signResponse the sign response
   * @param parameters optional processing parameters
   * @throws DocumentProcessingException for validation errors
   */
  protected void performAdditionalAdesValidation(final X adesObject, final X509Certificate signingCertificate,
      final SignTaskData signTaskData, final SignRequestWrapper signRequest, final SignResponseWrapper signResponse,
      final SignResponseProcessingParameters parameters) throws DocumentProcessingException {

    log.debug("{}: No additional AdES validation perfomed by {}", CorrelationID.id(), this.getClass().getSimpleName());
  }

  /** {@inheritDoc} */
  @Nonnull
  @Override
  public SignResponseProcessingConfig getProcessingConfiguration() {
    return this.processingConfiguration != null
        ? this.processingConfiguration
        : SignResponseProcessingConfig.defaultSignResponseProcessingConfig();
  }

  /**
   * Assigns the processing configuration.
   *
   * @param processingConfiguration processing configuration
   */
  public void setProcessingConfiguration(final SignResponseProcessingConfig processingConfiguration) {
    if (processingConfiguration != null) {
      this.processingConfiguration = processingConfiguration;
    }
  }

  /**
   * Gets the algorithm registry. If none has been configured, the {@link AlgorithmRegistrySingleton} will be used.
   *
   * @return the algorithm registry to use
   */
  protected AlgorithmRegistry getAlgorithmRegistry() {
    return this.algorithmRegistry != null
        ? this.algorithmRegistry
        : AlgorithmRegistrySingleton.getInstance();
  }

  /**
   * Assigns the algorithm registry to use.
   *
   * @param algorithmRegistry the algorithm registry to use
   */
  public void setAlgorithmRegistry(final AlgorithmRegistry algorithmRegistry) {
    this.algorithmRegistry = algorithmRegistry;
  }

  /**
   * Ensures that the {@code processingConfiguration} property is assigned. By default
   * {@link SignResponseProcessingConfig#defaultSignResponseProcessingConfig()} is used.
   *
   * <p>
   * Note: If executing in a Spring Framework environment this method is automatically invoked after all properties have
   * been assigned. Otherwise it should be explicitly invoked.
   * </p>
   *
   * @throws Exception for init errors
   */
  @PostConstruct
  public void afterPropertiesSet() throws Exception {
    if (this.processingConfiguration == null) {
      this.processingConfiguration = SignResponseProcessingConfig.defaultSignResponseProcessingConfig();
    }
  }

}
