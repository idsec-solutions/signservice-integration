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
package se.idsec.signservice.integration.app.rest;

import java.util.Base64;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.ExtendedSignServiceIntegrationService;
import se.idsec.signservice.integration.ProcessSignResponseInput;
import se.idsec.signservice.integration.SignRequestData;
import se.idsec.signservice.integration.SignRequestInput;
import se.idsec.signservice.integration.SignResponseCancelStatusException;
import se.idsec.signservice.integration.SignResponseErrorStatusException;
import se.idsec.signservice.integration.SignResponseProcessingParameters;
import se.idsec.signservice.integration.SignServiceIntegrationService;
import se.idsec.signservice.integration.SignatureResult;
import se.idsec.signservice.integration.config.IntegrationServiceDefaultConfiguration;
import se.idsec.signservice.integration.config.PolicyNotFoundException;
import se.idsec.signservice.integration.core.SignatureState;
import se.idsec.signservice.integration.core.error.InputValidationException;
import se.idsec.signservice.integration.core.error.SignServiceIntegrationException;
import se.idsec.signservice.integration.core.error.impl.SignServiceIntegrationErrorUtils;
import se.idsec.signservice.integration.document.pdf.PdfSignaturePageFullException;
import se.idsec.signservice.integration.document.pdf.PdfSignaturePagePreferences;
import se.idsec.signservice.integration.document.pdf.PreparePdfSignaturePageInput;
import se.idsec.signservice.integration.document.pdf.PreparedPdfDocument;

/**
 * An implementation of the {@link SignServiceIntegrationService} that implements its methods by invoking the
 * SignService Integration REST Service.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Service
@ConditionalOnProperty(name = "signservice.rest.enabled", havingValue = "true")
@Slf4j
public class RestClientSignServiceIntegrationService implements ExtendedSignServiceIntegrationService {

  @Autowired
  @Setter
  private RestTemplate restTemplate;

  @Autowired
  @Qualifier("restServerUrl")
  @Setter
  private String restServerUrl;

  /** {@inheritDoc} */
  @Override
  public SignRequestData createSignRequest(final SignRequestInput signRequestInput)
      throws InputValidationException, SignServiceIntegrationException {

    final String policy = signRequestInput.getPolicy() != null ? signRequestInput.getPolicy() : "default";

    try {
      final SignRequestData signRequestData =
          this.restTemplate.postForObject(this.restServerUrl + "/v1/create/{policy}", signRequestInput, SignRequestData.class, policy);

      log.debug("SignRequestData: {}", signRequestData);

      return signRequestData;
    }
    catch (RestClientException e) {
      if (e instanceof HttpClientErrorException) {
        final String errorBody = ((HttpClientErrorException) e).getResponseBodyAsString();
        final Exception ex = SignServiceIntegrationErrorUtils.toException(errorBody);
        log.error("Error creating sign request", e);
        if (InputValidationException.class.isInstance(ex)) {
          throw InputValidationException.class.cast(ex);
        }
        else if (SignServiceIntegrationException.class.isInstance(ex)) {
          throw SignServiceIntegrationException.class.cast(ex);
        }
      }
      log.error("Error creating sign request", e);
      throw e;
    }
  }

  /** {@inheritDoc} */
  @Override
  public SignatureResult processSignResponse(final String signResponse, final String relayState,
      final SignatureState state, final SignResponseProcessingParameters parameters)
      throws SignResponseCancelStatusException, SignResponseErrorStatusException, SignServiceIntegrationException {

    final ProcessSignResponseInput input = ProcessSignResponseInput.builder()
      .signResponse(signResponse)
      .relayState(relayState)
      .state(state)
      .parameters(parameters)
      .build();

    try {
      final SignatureResult result =
          this.restTemplate.postForObject(this.restServerUrl + "/v1/process", input, SignatureResult.class);
      return result;
    }
    catch (RestClientException e) {
      if (e instanceof HttpClientErrorException) {
        final String errorBody = ((HttpClientErrorException) e).getResponseBodyAsString();
        final Exception ex = SignServiceIntegrationErrorUtils.toException(errorBody);
        if (InputValidationException.class.isInstance(ex)) {
          throw InputValidationException.class.cast(ex);
        }
        else if (SignResponseCancelStatusException.class.isInstance(ex)) {
          throw SignResponseCancelStatusException.class.cast(ex);
        }
        else if (SignResponseErrorStatusException.class.isInstance(ex)) {
          throw SignResponseErrorStatusException.class.cast(ex);
        }
        else if (SignServiceIntegrationException.class.isInstance(ex)) {
          throw SignServiceIntegrationException.class.cast(ex);
        }
      }
      throw e;
    }
  }

  @Override
  public PreparedPdfDocument preparePdfSignaturePage(final String policy, final byte[] pdfDocument,
      final PdfSignaturePagePreferences signaturePagePreferences)
      throws InputValidationException, PdfSignaturePageFullException, SignServiceIntegrationException {

    final PreparePdfSignaturePageInput input = PreparePdfSignaturePageInput.builder()
      .pdfDocument(Base64.getEncoder().encodeToString(pdfDocument))
      .signaturePagePreferences(signaturePagePreferences)
      .build();

    try {
      final PreparedPdfDocument result = this.restTemplate.postForObject(
        this.restServerUrl + "/v1/prepare/{policy}", input, PreparedPdfDocument.class, policy);
      return result;
    }
    catch (RestClientException e) {
      if (e instanceof HttpClientErrorException) {
        final String errorBody = ((HttpClientErrorException) e).getResponseBodyAsString();
        final Exception ex = SignServiceIntegrationErrorUtils.toException(errorBody);
        if (InputValidationException.class.isInstance(ex)) {
          throw InputValidationException.class.cast(ex);
        }
        else if (PdfSignaturePageFullException.class.isInstance(ex)) {
          throw PdfSignaturePageFullException.class.cast(ex);
        }
        else if (SignServiceIntegrationException.class.isInstance(ex)) {
          throw SignServiceIntegrationException.class.cast(ex);
        }
      }
      throw e;
    }
  }

  @Override
  public IntegrationServiceDefaultConfiguration getConfiguration(final String policy) throws PolicyNotFoundException {
    return null;
  }

  @Override
  public List<String> getPolicies() {
    return null;
  }

  /** {@inheritDoc} */
  @Override
  public String getVersion() {
    return null;
  }

  // private HttpHeaders getHeaders() {
  // final HttpHeaders headers = new HttpHeaders();
  // headers.set("Authorization", this.authorizationHeader);
  // return headers;
  // }

}
