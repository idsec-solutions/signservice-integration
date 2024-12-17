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
package se.idsec.signservice.integration.document;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import se.idsec.signservice.integration.SignResponseProcessingParameters;
import se.idsec.signservice.integration.core.error.SignServiceIntegrationException;
import se.idsec.signservice.integration.document.ades.AdesObject;
import se.idsec.signservice.integration.dss.SignRequestWrapper;
import se.idsec.signservice.integration.dss.SignResponseWrapper;
import se.idsec.signservice.integration.process.SignResponseProcessingConfig;
import se.swedenconnect.schemas.csig.dssext_1_1.SignTaskData;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Interface for a processor of a signed document.
 *
 * @param <T> the type of documents that this processor handles
 * @param <X> the type of AdES objects used for this document type
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface SignedDocumentProcessor<T, X extends AdesObject> extends DocumentProcessor<T> {

  /**
   * Predicate that tells if the supplied sign data can be handled by this processor.
   *
   * @param signData the signed data
   * @return if the data can be processed by this instance true is returned, otherwise false
   */
  boolean supports(@Nonnull final SignTaskData signData);

  /**
   * Given a {@code SignTaskData} received in a sign response containing a signature and a {@code TbsDocument} from the
   * corresponding sign request the method compiles a complete signed document.
   *
   * @param tbsDocument the to-be-signed document
   * @param signedData the signed data (signature)
   * @param signerCertificateChain the certificate chain for the signer (starting with the signer certificate and
   *     ending with the root)
   * @param signRequest the corresponding sign request
   * @param parameters processing parameters received from the caller
   * @return a compiled signed document
   * @throws SignServiceIntegrationException for processing errors
   */
  CompiledSignedDocument<T, X> buildSignedDocument(@Nonnull final TbsDocument tbsDocument,
      @Nonnull final SignTaskData signedData,
      @Nonnull final List<X509Certificate> signerCertificateChain,
      @Nonnull final SignRequestWrapper signRequest,
      @Nullable final SignResponseProcessingParameters parameters) throws SignServiceIntegrationException;

  /**
   * Given a compiled signed document the method validates its signature.
   * <p>
   * The signer certificate has already been validated so explicit validation of the signer certificate is not needed.
   * </p>
   *
   * @param signedDocument the document to validate
   * @param signerCertificate the signer certificate
   * @param signTaskData the sign task data
   * @param parameters processing parameters received from the caller
   * @param requestID the ID for this operation (for logging)
   * @throws SignServiceIntegrationException for validation errors
   */
  void validateSignedDocument(@Nonnull final T signedDocument,
      @Nonnull final X509Certificate signerCertificate,
      @Nonnull final SignTaskData signTaskData,
      @Nullable final SignResponseProcessingParameters parameters,
      @Nonnull final String requestID) throws SignServiceIntegrationException;

  /**
   * Given a AdES object from the signature the method validates that it is valid.
   *
   * @param adesObject the AdES object
   * @param signingCertificate the signing certificate
   * @param signTaskData the sign task data
   * @param signRequest the sign request
   * @param signResponse the sign response
   * @param parameters processing parameters received from the caller
   * @throws SignServiceIntegrationException for validation errors
   */
  void validateAdesObject(@Nonnull final X adesObject,
      @Nonnull final X509Certificate signingCertificate,
      @Nonnull final SignTaskData signTaskData,
      @Nonnull final SignRequestWrapper signRequest,
      @Nonnull final SignResponseWrapper signResponse,
      @Nullable final SignResponseProcessingParameters parameters) throws SignServiceIntegrationException;

  /**
   * Gets the processing configuration that this processor is configured with.
   *
   * @return the processing configuration
   */
  @Nonnull
  SignResponseProcessingConfig getProcessingConfiguration();
}
