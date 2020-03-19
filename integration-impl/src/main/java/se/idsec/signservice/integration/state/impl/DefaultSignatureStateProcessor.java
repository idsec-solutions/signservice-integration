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

import javax.xml.bind.JAXBException;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.SignRequestInput;
import se.idsec.signservice.integration.config.ConfigurationManager;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.SignatureState;
import se.idsec.signservice.integration.core.error.ErrorCode;
import se.idsec.signservice.integration.dss.SignRequestWrapper;
import se.idsec.signservice.integration.state.IntegrationServiceStateCache;
import se.idsec.signservice.integration.state.SignatureSessionState;
import se.idsec.signservice.integration.state.SignatureStateProcessor;
import se.idsec.signservice.integration.state.StateException;
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
public class DefaultSignatureStateProcessor implements SignatureStateProcessor, InitializingBean {

  /** The state cache. */
  private IntegrationServiceStateCache stateCache;
  
  /** Handles policy configurations. */
  private ConfigurationManager configurationManager;
  
  /** {@inheritDoc} */
  @Override
  public SignatureState createSignatureState(final SignRequestInput requestInput, final SignRequestWrapper signRequest, final boolean stateless) {
    
    // Build a session state ...
    //
    SignatureSessionState sessionState = SignatureSessionState.builder()
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
    SignatureState completeState = DefaultSignatureState.builder()
        .id(signRequest.getRequestID())
        .state(sessionState)
        .build();
    
    if (stateless) {
      return completeState;
    }
    else {
      this.stateCache.put(signRequest.getRequestID(), completeState);
      return DefaultSignatureState.builder().id(signRequest.getRequestID()).build();
    }
  }

  /** {@inheritDoc} */
  @Override
  public SignatureSessionState getSignatureState(final SignatureState inputState) throws StateException {
    
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
      final SignatureState state = this.stateCache.get(inputState.getId(), true);
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
      if (!SignatureSessionState.class.isInstance(inputState.getState())) {
        final String msg = String.format("Could not read supplied state for ID '%s'", inputState.getId());
        log.error("{} - Supplied state is of type '{}'", msg, inputState.getState().getClass().getName());
        throw new StateException(new ErrorCode.Code("format-error"), msg);
      }
      // Before accepting the signature state make sure that the policy used really says "stateless".
      //
      final SignatureSessionState state = SignatureSessionState.class.cast(inputState.getState());
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

  /** {@inheritDoc} */
  @Override
  public void afterPropertiesSet() throws Exception {
    Assert.notNull(this.stateCache, "The 'stateCache' property must be assigned");
    Assert.notNull(this.configurationManager, "The 'configurationManager' property must be assigned");
  }
}
