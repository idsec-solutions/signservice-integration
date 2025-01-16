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
package se.idsec.signservice.integration.process;

import se.idsec.signservice.integration.dss.SignRequestWrapper;

/**
 * Representation of the SignRequest processing result. Used as the return type of
 * {@link SignRequestProcessor#process(se.idsec.signservice.integration.SignRequestInput, String, se.idsec.signservice.integration.config.IntegrationServiceConfiguration)}.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class SignRequestProcessingResult {

  /** The SignRequest (unsigned). */
  private final SignRequestWrapper signRequest;

  /** The signed and Base64-encoded SignRequest. */
  private final String encodedSignRequest;

  /**
   * Constructor.
   *
   * @param signRequest
   *          the SignRequest
   * @param encodedSignRequest
   *          the signed and Base64-encoded SignRequest
   */
  public SignRequestProcessingResult(final SignRequestWrapper signRequest, final String encodedSignRequest) {
    this.signRequest = signRequest;
    this.encodedSignRequest = encodedSignRequest;
  }

  /**
   * Gets the (unsigned) SignRequest.
   *
   * @return the SignRequest
   */
  public SignRequestWrapper getSignRequest() {
    return this.signRequest;
  }

  /**
   * Gets the signed and Base64-encoded SignRequest.
   *
   * @return the signed and Base64-encoded SignRequest
   */
  public String getEncodedSignRequest() {
    return this.encodedSignRequest;
  }

}
