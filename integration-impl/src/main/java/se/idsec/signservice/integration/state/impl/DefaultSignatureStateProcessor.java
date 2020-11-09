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
package se.idsec.signservice.integration.state.impl;

import java.io.IOException;
import java.io.Serializable;

import javax.annotation.PostConstruct;
import javax.xml.bind.JAXBException;

import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.SignRequestInput;
import se.idsec.signservice.integration.SignServiceIntegrationService;
import se.idsec.signservice.integration.config.ConfigurationManager;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.SignatureState;
import se.idsec.signservice.integration.core.error.ErrorCode;
import se.idsec.signservice.integration.core.error.NoAccessException;
import se.idsec.signservice.integration.dss.SignRequestWrapper;
import se.idsec.signservice.integration.state.CacheableSignatureState;
import se.idsec.signservice.integration.state.IntegrationServiceStateCache;
import se.idsec.signservice.integration.state.SignatureSessionState;
import se.idsec.signservice.integration.state.SignatureStateProcessor;
import se.idsec.signservice.integration.state.StateException;
import se.idsec.signservice.utils.AssertThat;
import se.idsec.signservice.xml.DOMUtils;
import se.idsec.signservice.xml.InternalXMLException;
import se.idsec.signservice.xml.JAXBMarshaller;

/**
 * Default implementation for signature state processing.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class DefaultSignatureStateProcessor implements SignatureStateProcessor {

  /** The state cache. */
  private IntegrationServiceStateCache stateCache;

  /** Handles policy configurations. */
  private ConfigurationManager configurationManager;

  /** Should state objects be Base64-encoded? */
  private boolean base64Encoded = false;

  /** For JSON deserialization. */
  private ObjectMapper objectMapper = new ObjectMapper();

  /** {@inheritDoc} */
  @Override
  public SignatureState createSignatureState(
      final SignRequestInput requestInput, final SignRequestWrapper signRequest, final boolean stateless) {

    // Build a session state ...
    //
    SignatureSessionState sessionState = SignatureSessionState.builder()
      .ownerId(requestInput.getExtensionValue(SignServiceIntegrationService.OWNER_ID_EXTENSION_KEY))
      .correlationId(requestInput.getCorrelationId())
      .policy(requestInput.getPolicy())
      .expectedReturnUrl(requestInput.getReturnUrl())
      .tbsDocuments(requestInput.getTbsDocuments())
      .signMessage(requestInput.getSignMessageParameters())
      .build();

    // If we are running in stateless mode we add the Base64-encoded SignRequest to the state, since the
    // SignRequest instance itself isn't something we can serialize to JSON (which will be done if we are
    // running as a REST-service).
    //
    if (stateless) {
      try {
        final String encodedSignRequest = DOMUtils.nodeToBase64(JAXBMarshaller.marshall(signRequest.getWrappedSignRequest()));
        sessionState.setEncodedSignRequest(encodedSignRequest);
      }
      catch (JAXBException e) {
        // This should never happen since the same SignRequest was marshalled during the process phase,
        // and if wouldn't have been ok, it would have been reported at that stage.
        throw new InternalXMLException("Failed to marshall SignRequest", e);
      }
    }
    else {
      sessionState.setSignRequest(signRequest);
    }

    // If we are running in a stateless mode we don't cache anything, we simply return the state
    // and leave it up to the caller to supply it in the next call.
    // If we are running in a stateful mode we cache the complete state and return a simple state
    // holding just the requestID.
    //
    CacheableSignatureState completeState = DefaultSignatureState.builder()
      .id(signRequest.getRequestID())
      .state(sessionState)
      .build();

    if (stateless) {
      if (this.base64Encoded) {
        try {
          return EncodedSignatureState.builder()
            .id(signRequest.getRequestID())
            .state(new EncodedSignatureSessionState(sessionState))
            .build();
        }
        catch (IOException e) {
          throw new RuntimeException("Failed to serialize state", e);
        }
      }
      return completeState;
    }
    else {
      this.stateCache.put(signRequest.getRequestID(), completeState);
      return DefaultSignatureState.builder().id(signRequest.getRequestID()).build();
    }
  }

  /** {@inheritDoc} */
  @Override
  public SignatureSessionState getSignatureState(final SignatureState inputState, final String requesterId)
      throws StateException, NoAccessException {

    if (inputState == null) {
      final String msg = "No signature state supplied";
      log.error(msg);
      throw new StateException(new ErrorCode.Code("missing-input-state"), msg);
    }
    if (inputState.getId() == null) {
      final String msg = "Missing ID in received state";
      log.error(msg);
      throw new StateException(new ErrorCode.Code("format-error"), msg);
    }
    log.debug("Processing signature state '{}'", inputState.getId());

    if (inputState.getState() == null) {
      // This indicates that the active policy is "stateful". Go get the SignatureState from the
      // cache.
      //
      final SignatureState state = this.stateCache.get(inputState.getId(), true, requesterId);
      if (state == null) {
        final String msg = String.format("No signature state found for ID '%s'", inputState.getId());
        log.info(msg);
        throw new StateException(new ErrorCode.Code("not-found"), msg);
      }
      return SignatureSessionState.class.cast(state.getState());
    }
    else {
      // This means that we are running in stateless mode.
      //
      final Serializable receivedState = inputState.getState();
      SignatureSessionState state = null;

      if (SignatureSessionState.class.isInstance(receivedState)) {
        state = SignatureSessionState.class.cast(inputState.getState());
      }
      else if (EncodedSignatureSessionState.class.isInstance(receivedState)) {
        EncodedSignatureSessionState encodedState = EncodedSignatureSessionState.class.cast(inputState.getState());
        try {
          state = encodedState.getSignatureSessionState();
        }
        catch (IOException e) {
          throw new StateException(new ErrorCode.Code("format-error"), "Failed to deserialize state", e);
        }
      }
      else {
        // We received this as part of a JSON object. Let's deserialize the string into a
        // SignatureSessionState instance.
        //
        try {
          if (this.base64Encoded) {
            final EncodedSignatureSessionState encodedState = this.objectMapper.convertValue(receivedState,
              EncodedSignatureSessionState.class);
            state = encodedState.getSignatureSessionState();
          }
          else {
            state = this.objectMapper.convertValue(receivedState, SignatureSessionState.class);
          }
        }
        catch (Exception e) {
          final String msg = String.format("Could not read supplied state for ID '%s'", inputState.getId());
          log.error("{} - Supplied state is of type '{}'. Contents: {}",
            msg, inputState.getState().getClass().getName(), String.class.cast(receivedState));
          throw new StateException(new ErrorCode.Code("format-error"), msg);
        }
      }
      if (state == null) {
        final String msg = String.format("Could not read supplied state for ID '%s'", inputState.getId());
        log.error("{} - Supplied state is of type '{}'", msg, inputState.getState().getClass().getName());
        throw new StateException(new ErrorCode.Code("format-error"), msg);
      }
      // Before accepting the signature state make sure that the policy used really says "stateless".
      //
      final IntegrationServiceConfiguration config = this.configurationManager.getConfiguration(state.getPolicy());
      if (config == null) {
        final String msg = String.format("Signature state with ID '%s' referenced policy '%s' which is not available",
          inputState.getId(), state.getPolicy());
        log.error(msg);
        throw new StateException(new ErrorCode.Code("policy-error"), msg);
      }
      if (!config.isStateless()) {
        // We received a signature session state even though we are running in stateless mode. Probably the
        // caller that has misunderstood things ...
        //
        final String msg = String.format("Signature state with ID '%s' used policy '%s', but this policy is stateless"
            + " and we still received session state - bad request", inputState.getId(), state.getPolicy());
        log.error(msg);
        throw new StateException(new ErrorCode.Code("policy-error"), msg);
      }
      return state;
    }
  }

  /** {@inheritDoc} */
  @Override
  public IntegrationServiceStateCache getStateCache() {
    return this.stateCache;
  }

  /**
   * Assigns the state cache.
   * 
   * @param stateCache
   *          the state cache
   */
  public void setStateCache(final IntegrationServiceStateCache stateCache) {
    this.stateCache = stateCache;
  }

  /**
   * Assigns the policy configuration manager bean.
   * 
   * @param configurationManager
   *          the policy configuration manager
   */
  public void setConfigurationManager(final ConfigurationManager configurationManager) {
    this.configurationManager = configurationManager;
  }

  /**
   * Tells whether we should Base64 encode the state objects if running in a stateless mode.
   * 
   * @param base64Encoded
   *          true if objects should be encoded
   */
  public void setBase64Encoded(final boolean base64Encoded) {
    this.base64Encoded = base64Encoded;
  }

  /**
   * Ensures that all required properties have been assigned.
   * 
   * <p>
   * Note: If executing in a Spring Framework environment this method is automatically invoked after all properties have
   * been assigned. Otherwise it should be explicitly invoked.
   * </p>
   * 
   * @throws Exception
   *           if not all settings are correct
   */
  @PostConstruct
  public void afterPropertiesSet() throws Exception {
    AssertThat.isNotNull(this.configurationManager, "The 'configurationManager' property must be assigned");

    // If all policies are stateless, we don't need a cache ...
    //
    if (this.stateCache == null) {
      boolean cacheNeeded = false;
      for (String policy : this.configurationManager.getPolicies()) {
        if (!this.configurationManager.getConfiguration(policy).isStateless()) {
          cacheNeeded = true;
          break;
        }
      }
      if (cacheNeeded) {
        throw new IllegalArgumentException("The 'stateCache' property must be assigned");
      }
      else {
        this.stateCache = new InMemoryIntegrationServiceStateCache();
      }
    }
  }
}
