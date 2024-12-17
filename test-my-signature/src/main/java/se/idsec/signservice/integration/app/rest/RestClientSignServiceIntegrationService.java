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
package se.idsec.signservice.integration.app.rest;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import se.idsec.signservice.integration.ExtendedSignServiceIntegrationService;
import se.idsec.signservice.integration.ProcessSignResponseInput;
import se.idsec.signservice.integration.SignRequestData;
import se.idsec.signservice.integration.SignRequestInput;
import se.idsec.signservice.integration.SignResponseErrorStatusException;
import se.idsec.signservice.integration.SignResponseProcessingParameters;
import se.idsec.signservice.integration.SignServiceIntegrationService;
import se.idsec.signservice.integration.SignatureResult;
import se.idsec.signservice.integration.config.IntegrationServiceDefaultConfiguration;
import se.idsec.signservice.integration.config.PolicyNotFoundException;
import se.idsec.signservice.integration.core.SignatureState;
import se.idsec.signservice.integration.core.error.SignServiceIntegrationException;
import se.idsec.signservice.integration.core.error.impl.SignServiceIntegrationErrorUtils;
import se.idsec.signservice.integration.document.pdf.PdfSignaturePagePreferences;
import se.idsec.signservice.integration.document.pdf.PreparePdfSignaturePageInput;
import se.idsec.signservice.integration.document.pdf.PreparedPdfDocument;

import java.util.Base64;
import java.util.List;

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

  @Value("${signservice.default-policy-name:default}")
  @Setter
  private String policyName;

  /** {@inheritDoc} */
  @Nonnull
  @Override
  public SignRequestData createSignRequest(@Nonnull final SignRequestInput signRequestInput,
      @Nullable final String callerId) throws SignServiceIntegrationException {

    final String policy = signRequestInput.getPolicy() != null ? signRequestInput.getPolicy() : this.policyName;

    try {
      final SignRequestData signRequestData =
          this.restTemplate.postForObject(this.restServerUrl + "/v1/create/{policy}", signRequestInput,
              SignRequestData.class, policy);

      log.debug("SignRequestData: {}", signRequestData);

      return signRequestData;
    }
    catch (final RestClientException e) {
      log.error("Error creating sign request", e);
      if (e instanceof final HttpClientErrorException httpClientErrorException) {
        try {
          SignServiceIntegrationErrorUtils.throwSignServiceException(
              httpClientErrorException.getResponseBodyAsString());
        }
        catch (final SignResponseErrorStatusException impossible) {
          throw new RuntimeException(impossible);
        }
      }
      throw e;
    }
  }

  /** {@inheritDoc} */
  @Nonnull
  @Override
  public SignatureResult processSignResponse(@Nonnull final String signResponse, @Nonnull final String relayState,
      @Nonnull final SignatureState state, @Nullable final SignResponseProcessingParameters parameters,
      @Nullable final String callerId) throws SignResponseErrorStatusException, SignServiceIntegrationException {

    final ProcessSignResponseInput input = ProcessSignResponseInput.builder()
        .signResponse(signResponse)
        .relayState(relayState)
        .state(state)
        .parameters(parameters)
        .build();

    try {
      return this.restTemplate.postForObject(this.restServerUrl + "/v1/process", input, SignatureResult.class);
    }
    catch (final RestClientException e) {
      if (e instanceof final HttpClientErrorException httpClientErrorException) {
        SignServiceIntegrationErrorUtils.throwSignServiceException(httpClientErrorException.getResponseBodyAsString());
      }
      throw e;
    }
  }

  @Override
  public PreparedPdfDocument preparePdfDocument(@Nullable final String policy, @Nonnull final byte[] pdfDocument,
      @Nullable final PdfSignaturePagePreferences signaturePagePreferences,
      @Nullable final Boolean returnDocumentReference, @Nullable final String callerId)
      throws SignServiceIntegrationException {

    final PreparePdfSignaturePageInput input = PreparePdfSignaturePageInput.builder()
        .pdfDocument(Base64.getEncoder().encodeToString(pdfDocument))
        .signaturePagePreferences(signaturePagePreferences)
        .build();

    try {
      final MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
      if (returnDocumentReference != null) {
        headers.add("returnDocReference", returnDocumentReference.toString());
      }
      final HttpEntity<PreparePdfSignaturePageInput> request = new HttpEntity<>(input, headers);
      return this.restTemplate.postForObject(
          this.restServerUrl + "/v1/prepare/{policy}", request, PreparedPdfDocument.class, policy);
    }
    catch (final RestClientException e) {
      if (e instanceof final HttpClientErrorException httpClientErrorException) {
        try {
          SignServiceIntegrationErrorUtils.throwSignServiceException(
              httpClientErrorException.getResponseBodyAsString());
        }
        catch (final SignResponseErrorStatusException statusException) {
          // Should never happen ...
          throw new RuntimeException(statusException);
        }
      }
      throw e;
    }
  }

  @Nonnull
  @Override
  public IntegrationServiceDefaultConfiguration getConfiguration(@Nullable final String policy)
      throws PolicyNotFoundException {
    throw new RuntimeException("Not implemented yet");
  }

  @Nonnull
  @Override
  public List<String> getPolicies() {
    throw new RuntimeException("Not implemented yet");
  }

  /** {@inheritDoc} */
  @Nonnull
  @Override
  public String getVersion() {
    throw new RuntimeException("Not implemented yet");
  }

}
