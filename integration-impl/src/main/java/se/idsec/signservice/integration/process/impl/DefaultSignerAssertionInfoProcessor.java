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
package se.idsec.signservice.integration.process.impl;

import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.annotation.PostConstruct;
import javax.xml.bind.JAXBException;

import org.apache.commons.lang.StringUtils;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.SignResponseProcessingParameters;
import se.idsec.signservice.integration.authentication.SignerAssertionInformation;
import se.idsec.signservice.integration.authentication.SignerAssertionInformation.SignerAssertionInformationBuilder;
import se.idsec.signservice.integration.authentication.SignerIdentityAttributeValue;
import se.idsec.signservice.integration.core.error.ErrorCode;
import se.idsec.signservice.integration.core.error.SignServiceIntegrationException;
import se.idsec.signservice.integration.core.error.impl.SignServiceProtocolException;
import se.idsec.signservice.integration.core.impl.CorrelationID;
import se.idsec.signservice.integration.dss.DssUtils;
import se.idsec.signservice.integration.dss.SignRequestWrapper;
import se.idsec.signservice.integration.dss.SignResponseWrapper;
import se.idsec.signservice.integration.process.SignResponseProcessingConfig;
import se.idsec.signservice.integration.signmessage.SignMessageProcessor;
import se.idsec.signservice.integration.state.SignatureSessionState;
import se.idsec.signservice.xml.DOMUtils;
import se.idsec.signservice.xml.InternalXMLException;
import se.idsec.signservice.xml.JAXBUnmarshaller;
import se.swedenconnect.schemas.csig.dssext_1_1.ContextInfo;
import se.swedenconnect.schemas.csig.dssext_1_1.MappedAttributeType;
import se.swedenconnect.schemas.csig.dssext_1_1.PreferredSAMLAttributeNameType;
import se.swedenconnect.schemas.csig.dssext_1_1.RequestedCertAttributes;
import se.swedenconnect.schemas.csig.dssext_1_1.SignerAssertionInfo;
import se.swedenconnect.schemas.saml_2_0.assertion.Assertion;
import se.swedenconnect.schemas.saml_2_0.assertion.AttributeStatement;

/**
 * Default implementation of the {@link SignerAssertionInfoProcessor} interface.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class DefaultSignerAssertionInfoProcessor implements SignerAssertionInfoProcessor {

  /** Processing config. */
  protected SignResponseProcessingConfig processingConfig = SignResponseProcessingConfig.defaultSignResponseProcessingConfig();

  /** {@inheritDoc} */
  @Override
  public SignerAssertionInformation processSignerAssertionInfo(
      final SignResponseWrapper signResponse, final SignatureSessionState state,
      final SignResponseProcessingParameters parameters) throws SignServiceIntegrationException {

    final SignerAssertionInfo signerAssertionInfo = signResponse.getSignResponseExtension().getSignerAssertionInfo();
    if (signerAssertionInfo == null) {
      final String msg =
          String.format("No SignerAssertionInfo available in SignResponse [request-id='%s']", state.getSignRequest().getRequestID());
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new SignServiceProtocolException(msg);
    }

    final SignerAssertionInformationBuilder builder = SignerAssertionInformation.builder();
    final SignRequestWrapper signRequest = state.getSignRequest();

    // Attributes
    // Validate that we got all required attributes ...
    //
    final List<SignerIdentityAttributeValue> attributes = this.processAttributes(signerAssertionInfo, signRequest);
    builder.signerAttributes(attributes);

    // Get ContextInfo values ...
    //
    final ContextInfo contextInfo = signerAssertionInfo.getContextInfo();
    if (contextInfo == null) {
      final String msg =
          String.format("No SignerAssertionInfo/ContextInfo available in SignResponse [request-id='%s']", signRequest.getRequestID());
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new SignServiceProtocolException(msg);
    }

    // IdentityProvider
    //
    if (contextInfo.getIdentityProvider() == null || StringUtils.isBlank(contextInfo.getIdentityProvider().getValue())) {
      final String msg = String.format("No SignerAssertionInfo/ContextInfo/IdentityProvider available in SignResponse [request-id='%s']",
        signRequest.getRequestID());
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new SignServiceProtocolException(msg);
    }
    if (!contextInfo.getIdentityProvider().getValue().equals(signRequest.getSignRequestExtension().getIdentityProvider().getValue())) {
      final String msg =
          String.format("IdentityProvider in SignResponse (%s) does not match provider given in SignRequest (%s) [request-id='%s']",
            contextInfo.getIdentityProvider().getValue(), signRequest.getSignRequestExtension().getIdentityProvider().getValue(),
            signRequest.getRequestID());
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new SignResponseProcessingException(new ErrorCode.Code("invalid-response"), msg);
    }
    builder.authnServiceID(contextInfo.getIdentityProvider().getValue());

    // AssertionRef
    //
    final String assertionRef = contextInfo.getAssertionRef();
    if (StringUtils.isBlank(assertionRef)) {
      final String msg = String.format(
        "No SignerAssertionInfo/ContextInfo/AssertionRef available in SignResponse [request-id='%s']", signRequest.getRequestID());
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new SignServiceProtocolException(msg);
    }
    builder.assertionReference(assertionRef);

    // Assertions ...
    //
    byte[] idpAssertion = null;
    if (!signerAssertionInfo.isSetSamlAssertions() || !signerAssertionInfo.getSamlAssertions().isSetAssertions()) {
      if (this.processingConfig.isRequireAssertion()) {
        final String msg =
            String.format("No SignerAssertionInfo/SamlAssertions present in SignResponse. Configuration requires this [request-id='%s']",
              signRequest.getRequestID());
        log.error("{}: {}", CorrelationID.id(), msg);
        throw new SignResponseProcessingException(new ErrorCode.Code("invalid-response"), msg);
      }
    }
    else {
      if (signerAssertionInfo.getSamlAssertions().getAssertions().size() == 1 && !this.processingConfig.isStrictProcessing()) {
        // If strict processing is turned off and we only got one assertion we trust that the SignService
        // included the assertion that corresponds to AssertionRef.
        //
        idpAssertion = signerAssertionInfo.getSamlAssertions().getAssertions().get(0);
        builder.assertion(Base64.getEncoder().encodeToString(idpAssertion));
      }
      // Find the assertion matching the AssertionRef ...
      else {
        for (final byte[] a : signerAssertionInfo.getSamlAssertions().getAssertions()) {
          try {
            final Assertion assertion = JAXBUnmarshaller.unmarshall(DOMUtils.bytesToDocument(a), Assertion.class);
            if (assertionRef.equals(assertion.getID())) {
              idpAssertion = a;
              break;
            }
            else {
              log.info("{}: Processing assertion with ID '%s' - no match with AssertionRef [request-id='{}']",
                assertion.getID(), signRequest.getRequestID());
            }
          }
          catch (final InternalXMLException | JAXBException e) {
            final String msg =
                String.format("Invalid SAML assertion found in SignerAssertionInfo/SamlAssertions - %s [request-id='%s']",
                  e.getMessage(), signRequest.getRequestID());
            log.error("{}: {}", CorrelationID.id(), msg);
            throw new SignResponseProcessingException(new ErrorCode.Code("invalid-response"), msg);
          }
        }
        if (idpAssertion != null) {
          builder.assertion(Base64.getEncoder().encodeToString(idpAssertion));
        }
        else {
          final String msg =
              String.format("No SAML assertion matching AssertionRef found in SignerAssertionInfo/SamlAssertions [request-id='%s']",
                signRequest.getRequestID());
          log.error("{}: {}", CorrelationID.id(), msg);
          throw new SignResponseProcessingException(new ErrorCode.Code("invalid-response"), msg);
        }
      }
    }

    // AuthenticationInstant
    //
    // This validation is essential. We want to ensure that the authentication instant is not too old. It must not be
    // before we actually sent our request. Furthermore, it must not be after the sign response was sent. In both cases
    // we take the allowed clock skew in account.
    //
    builder.authnInstant(
      this.processAuthenticationInstant(contextInfo, signRequest, signResponse));

    // AuthnContextClassRef
    //
    final String authnContextClassRef = contextInfo.getAuthnContextClassRef();
    if (StringUtils.isBlank(authnContextClassRef)) {
      final String msg = String.format(
        "No SignerAssertionInfo/ContextInfo/AuthnContextClassRef available in SignResponse [request-id='%s']", signRequest.getRequestID());
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new SignServiceProtocolException(msg);
    }

    // Get hold of the LoA from the request.
    final List<String> requestedAuthnContextClassRefs =
        Optional.ofNullable(signRequest.getSignRequestExtension().getCertRequestProperties().getAuthnContextClassRefs())
          .orElse(Collections.emptyList());

    // Did we require a sign message to be displayed?
    final boolean requireDisplaySignMessageProof = this.requireDisplaySignMessageProof(state);

    if (requestedAuthnContextClassRefs.contains(authnContextClassRef)) {
      // If display of SignMessage was required, we need the signMessageDigest attribute to be released.
      if (requireDisplaySignMessageProof) {
        String signMessageDigest = attributes.stream()
          .filter(a -> SignMessageProcessor.SIGN_MESSAGE_DIGEST_ATTRIBUTE.equals(a.getName()))
          .map(a -> a.getValue())
          .findFirst()
          .orElse(null);

        // OK, the signMessageDigest wasn't part of the SignerAssertionInfo/AttributeStatement element.
        // This is not really an error since version 1.3 of "DSS Extension for Federated Central Signing Services"
        // states the following:
        //
        // <saml:AttributeStatement> [Required]
        // This element of type saml:AttributeStatementType (see [SAML2.0]) holds subject attributes
        // obtained from the SAML assertion used to authenticate the signer at the Signing Service.
        // For integrity reasons, this element SHOULD only provide information about SAML attribute
        // values that maps to subject identity information in the signer's certificate.
        //
        // So, lets hope that we have an assertion ...
        //
        if (idpAssertion != null) {
          try {
            final Assertion assertion = JAXBUnmarshaller.unmarshall(DOMUtils.bytesToDocument(idpAssertion), Assertion.class);
            final AttributeStatement attributeStatement = DssUtils.getAttributeStatement(assertion);
            if (attributeStatement != null) {
              signMessageDigest = DssUtils.getAttributeValue(attributeStatement, SignMessageProcessor.SIGN_MESSAGE_DIGEST_ATTRIBUTE);
            }
          }
          catch (final InternalXMLException | JAXBException e) {
            final String msg =
                String.format("Invalid SAML assertion found in SignerAssertionInfo/SamlAssertions - %s [request-id='%s']",
                  e.getMessage(), signRequest.getRequestID());
            log.error("{}: {}", CorrelationID.id(), msg);
            throw new SignResponseProcessingException(new ErrorCode.Code("invalid-response"), msg);
          }
        }

        if (signMessageDigest == null) {
          final String msg = String.format(
            "Missing proof for displayed sign message (no signMessageDigest and no sigmessage authnContext) [request-id='%s']",
            signRequest.getRequestID());

          if (this.processingConfig.isRequireAssertion()) {
            log.error("{}: {}", CorrelationID.id(), msg);
            throw new SignResponseProcessingException(new ErrorCode.Code("invalid-authncontext"), msg);
          }
          else {
            // If we did not require assertions to be delivered, we can't fail here. We have to trust
            // that the sign service made sure that the signMessageDigest was received.
            //
            log.warn("{}: {}", CorrelationID.id(), msg);
          }
        }
        else if (this.processingConfig.isStrictProcessing()) {
          // Compare hash with our own hash of the sent SignMessage.
          // TODO
        }
      }
    }
    else {
      final String msg = String.format("Unexpected authnContextRef received - %s. %s was expected [request-id='%s']",
        authnContextClassRef, requestedAuthnContextClassRefs, signRequest.getRequestID());
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new SignResponseProcessingException(new ErrorCode.Code("invalid-authncontext"), msg);
    }
    builder.authnContextRef(authnContextClassRef);

    // AuthType
    //
    builder.authnType(contextInfo.getAuthType());

    return builder.build();
  }

  /**
   * Tells if the display of a sign message with a MustShow flag set was requested.
   *
   * @param state
   *          the state
   * @return if sign message display is required true is returned, otherwise false
   */
  protected boolean requireDisplaySignMessageProof(final SignatureSessionState state) {
    if (state.getSignMessage() != null && state.getSignMessage().getMustShow() != null) {
      return state.getSignMessage().getMustShow().booleanValue();
    }
    return false;
  }

  /**
   * Extracts the attributes from the response and validates that we received all attributes that were requested (if
   * strict processing is enabled).
   *
   * @param signerAssertionInfo
   *          the signer info (including the received attributes)
   * @param signRequest
   *          the request
   * @throws SignServiceIntegrationException
   *           for validation errors
   */
  protected List<SignerIdentityAttributeValue> processAttributes(final SignerAssertionInfo signerAssertionInfo,
      final SignRequestWrapper signRequest) throws SignServiceIntegrationException {

    if (signerAssertionInfo.getAttributeStatement() == null
        || signerAssertionInfo.getAttributeStatement().getAttributesAndEncryptedAttributes().isEmpty()) {
      final String msg = String.format("No SignerAssertionInfo/AttributeStatement available in SignResponse [request-id='%s']",
        signRequest.getRequestID());
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new SignServiceProtocolException(msg);
    }
    final List<SignerIdentityAttributeValue> attributes = DssUtils.fromAttributeStatement(signerAssertionInfo.getAttributeStatement());

    if (this.processingConfig.isStrictProcessing()) {
      final RequestedCertAttributes requestedAttributes =
          signRequest.getSignRequestExtension().getCertRequestProperties().getRequestedCertAttributes();
      for (final MappedAttributeType mat : requestedAttributes.getRequestedCertAttributes()) {
        if (!mat.isRequired() || StringUtils.isNotBlank(mat.getDefaultValue())) {
          // For non required attributes or those having a default value there is no requirement to
          // get it from the IdP or AA.
          continue;
        }
        boolean attrDelivered = false;
        for (final PreferredSAMLAttributeNameType attr : mat.getSamlAttributeNames()) {
          if (attributes.stream().filter(a -> a.getName().equals(attr.getValue())).findFirst().isPresent()) {
            log.trace("{}: Requested attribute '{}' was delivered by IdP/AA [request-id='{}']",
              CorrelationID.id(), attr.getValue(), signRequest.getRequestID());
            attrDelivered = true;
            break;
          }
        }
        if (!attrDelivered) {
          final String msg = String.format(
            "None of the requested attribute(s) %s were delivered in SignerAssertionInfo/AttributeStatement [request-id='%s']",
            mat.getSamlAttributeNames().stream().map(a -> a.getValue()).collect(Collectors.toList()), signRequest.getRequestID());
          log.error("{}: {}", CorrelationID.id(), msg);
          throw new SignResponseProcessingException(new ErrorCode.Code("invalid-response"), msg);
        }
      }
    }
    return attributes;
  }

  /**
   * Validates that the received authentication instant is OK.
   *
   * @param contextInfo
   *          the context info holding the authn instant
   * @param signRequest
   *          the sign request
   * @param signResponse
   *          the sign response
   * @throws SignServiceIntegrationException
   *           for validation errors
   */
  protected long processAuthenticationInstant(final ContextInfo contextInfo, final SignRequestWrapper signRequest,
      final SignResponseWrapper signResponse)
      throws SignServiceIntegrationException {

    if (contextInfo.getAuthenticationInstant() == null) {
      final String msg =
          String.format("No SignerAssertionInfo/ContextInfo/AuthenticationInstant available in SignResponse [request-id='%s']",
            signRequest.getRequestID());
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new SignServiceProtocolException(msg);
    }
    final long authnInstant = contextInfo.getAuthenticationInstant().toGregorianCalendar().getTimeInMillis();
    final long requestTime = signRequest.getSignRequestExtension().getRequestTime().toGregorianCalendar().getTimeInMillis();
    final long responseTime = signResponse.getSignResponseExtension().getResponseTime().toGregorianCalendar().getTimeInMillis();

    if (authnInstant + this.processingConfig.getAllowedClockSkew() < requestTime) {
      final String msg = String.format("Invalid authentication instant (%d). It is before the SignRequest was sent (%d) [request-id='%s']",
        authnInstant, requestTime, signRequest.getRequestID());
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new SignResponseProcessingException(new ErrorCode.Code("invalid-response"), msg);
    }
    if (authnInstant - this.processingConfig.getAllowedClockSkew() > responseTime) {
      final String msg = String.format("Invalid authentication instant (%d). It is after the SignResponse time (%d) [request-id='%s']",
        authnInstant, responseTime, signRequest.getRequestID());
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new SignResponseProcessingException(new ErrorCode.Code("invalid-response"), msg);
    }
    return authnInstant;
  }

  protected String processAuthnContextClassRef(final ContextInfo contextInfo, final SignRequestWrapper signRequest)
      throws SignServiceIntegrationException {

    final String authnContextClassRef = contextInfo.getAuthnContextClassRef();
    if (StringUtils.isBlank(authnContextClassRef)) {
      final String msg = String.format(
        "No SignerAssertionInfo/ContextInfo/AuthnContextClassRef available in SignResponse [request-id='%s']", signRequest.getRequestID());
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new SignServiceProtocolException(msg);
    }

    // Get hold of the LoA from the request.
    //
    final List<String> requestedAuthnContextClassRefs =
        signRequest.getSignRequestExtension().getCertRequestProperties().getAuthnContextClassRefs();

    if (requestedAuthnContextClassRefs != null && requestedAuthnContextClassRefs.contains(authnContextClassRef)) {
      // OK if:
      // If SM was required: signMessageDigest is present
      // If not required - OK always

      // AdditionalCheck: check hash
    }
    else {
      // OK if:
      // sigMessageUris allowed
      // Mapping exists
      // SignMessage was sent
    }

    return authnContextClassRef;
  }

  /**
   * Assigns the processing config settings.
   *
   * @param processingConfig
   *          the processing config settings
   */
  public void setProcessingConfig(final SignResponseProcessingConfig processingConfig) {
    this.processingConfig = processingConfig;
  }

  /**
   * Ensures that the {@code processingConfig} property is assigned. By default
   * {@link SignResponseProcessingConfig#defaultSignResponseProcessingConfig()} is used.
   *
   * <p>
   * Note: If executing in a Spring Framework environment this method is automatically invoked after all properties have
   * been assigned. Otherwise it should be explicitly invoked.
   * </p>
   */
  @PostConstruct
  public void afterPropertiesSet() {
    if (this.processingConfig == null) {
      this.processingConfig = SignResponseProcessingConfig.defaultSignResponseProcessingConfig();
    }
  }

}
