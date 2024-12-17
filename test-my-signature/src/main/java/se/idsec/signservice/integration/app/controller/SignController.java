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
package se.idsec.signservice.integration.app.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import se.idsec.signservice.integration.ExtendedSignServiceIntegrationService;
import se.idsec.signservice.integration.SignRequestData;
import se.idsec.signservice.integration.SignRequestInput;
import se.idsec.signservice.integration.SignResponseCancelStatusException;
import se.idsec.signservice.integration.SignResponseErrorStatusException;
import se.idsec.signservice.integration.SignatureResult;
import se.idsec.signservice.integration.authentication.AuthnRequirements;
import se.idsec.signservice.integration.authentication.SignerAssertionInformation;
import se.idsec.signservice.integration.authentication.SignerIdentityAttribute;
import se.idsec.signservice.integration.authentication.SignerIdentityAttributeValue;
import se.idsec.signservice.integration.core.SignatureState;
import se.idsec.signservice.integration.core.error.SignServiceIntegrationException;
import se.idsec.signservice.integration.document.DocumentType;
import se.idsec.signservice.integration.document.TbsDocument;
import se.idsec.signservice.integration.document.TbsDocument.AdesType;
import se.idsec.signservice.integration.document.TbsDocument.EtsiAdesRequirement;
import se.idsec.signservice.integration.document.TbsDocument.TbsDocumentBuilder;
import se.idsec.signservice.integration.document.pdf.PdfSignaturePagePreferences;
import se.idsec.signservice.integration.document.pdf.PreparedPdfDocument;
import se.idsec.signservice.integration.document.pdf.VisiblePdfSignatureUserInformation;
import se.idsec.signservice.integration.document.pdf.VisiblePdfSignatureUserInformation.SignerName;
import se.idsec.signservice.integration.signmessage.SignMessageMimeType;
import se.idsec.signservice.integration.signmessage.SignMessageParameters;
import se.swedenconnect.eid.sp.controller.ApplicationException;
import se.swedenconnect.eid.sp.controller.BaseController;
import se.swedenconnect.eid.sp.model.AttributeInfo;
import se.swedenconnect.eid.sp.model.AttributeInfoRegistry;
import se.swedenconnect.eid.sp.model.AuthenticationInfo;
import se.swedenconnect.eid.sp.model.LastAuthentication;
import se.swedenconnect.eid.sp.saml.TestMyEidAuthnRequestGeneratorContext;
import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.opensaml.sweid.saml2.authn.LevelOfAssuranceUris;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Controller for sign service integration.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Controller
@RequestMapping("/sign")
@Slf4j
public class SignController extends BaseController {

  /** The SignService integration service. */
  @Autowired
  private ExtendedSignServiceIntegrationService integrationService;

  /** Holds localized messages. */
  @Autowired
  private MessageSource messageSource;

  /** For displaying of SAML attributes. */
  @Autowired
  private AttributeInfoRegistry attributeInfoRegistry;

  @Autowired
  @Qualifier("DebugFlag")
  private Boolean debugFlag;

  @Autowired
  @Qualifier("debugReturnUrl")
  private String debugReturnUrl;

  @Autowired
  @Qualifier("signIntegrationBaseUrl")
  private String signIntegrationBaseUrl;

  @Autowired
  @Qualifier("signRequesterId")
  private String signRequesterId;

  @Value("${signservice.sign.type:application/xml}")
  @Setter
  private String signType;

  @Value("${signservice.default-policy-name:default}")
  @Setter
  private String policyName;

  @RequestMapping("/request")
  public ModelAndView sendSignRequest(final HttpServletRequest request, final HttpServletResponse response)
      throws ApplicationException {

    log.debug("Request for generating an SignRequest [client-ip-address='{}']", request.getRemoteAddr());

    final HttpSession session = request.getSession();
    final LastAuthentication lastAuthentication = (LastAuthentication) session.getAttribute("last-authentication");
    if (lastAuthentication == null) {
      log.error("There is no session information available about the last authentication - cannot sign");
      throw new ApplicationException("sp.msg.error.no-session");
    }

    final String correlationId = UUID.randomUUID().toString();
    final String givenName = lastAuthentication.getGivenName();

    try {

      final List<SignerIdentityAttributeValue> requestedAttributes = new ArrayList<>();
      final String[][] attrs = new String[][] {
          { AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER,
              lastAuthentication.getPersonalIdentityNumber() },
          { AttributeConstants.ATTRIBUTE_NAME_PRID, lastAuthentication.getPrid() },
          { AttributeConstants.ATTRIBUTE_NAME_GIVEN_NAME, givenName },
          { AttributeConstants.ATTRIBUTE_NAME_SN, lastAuthentication.getSurName() },
          { AttributeConstants.ATTRIBUTE_NAME_DISPLAY_NAME, lastAuthentication.getDisplayName() },
          { AttributeConstants.ATTRIBUTE_NAME_C, lastAuthentication.getCountry() }
      };
      for (final String[] a : attrs) {
        if (a[1] != null) {
          requestedAttributes.add(SignerIdentityAttributeValue.builder().name(a[0]).value(a[1]).build());
        }
      }

      final PreparedPdfDocument preparedPdfDocument = DocumentType.PDF.getMimeType().equals(this.signType)
          ? this.integrationService.preparePdfDocument(this.policyName,
          getSamplePdf(),
          PdfSignaturePagePreferences.builder()
              .visiblePdfSignatureUserInformation(
                  VisiblePdfSignatureUserInformation.toBuilder()
                      .fieldValue("idp", lastAuthentication.getIdp())
                      .signerName(SignerName.builder()
                          .signerAttribute(SignerIdentityAttribute.createBuilder()
                              .name(AttributeConstants.ATTRIBUTE_NAME_DISPLAY_NAME).build())
                          .build())
                      .build())
              .build(), Boolean.TRUE, null)
          : null;

      final SignMessageParameters signMessageParameters = SignMessageParameters.builder()
          .signMessage(givenName != null
              ? this.messageSource.getMessage("sp.msg.sign-message", new Object[] { givenName },
              LocaleContextHolder.getLocale())
              : this.messageSource.getMessage("sp.msg.sigm-message-noname", null, LocaleContextHolder.getLocale()))
          .performEncryption(true)
          .mimeType(SignMessageMimeType.TEXT)
          .mustShow(true)
          .build();

      session.setAttribute("sign-message", signMessageParameters.getSignMessage());

      final TbsDocumentBuilder tbsDocumentBuilder = TbsDocument.builder()
          .id(UUID.randomUUID().toString())
          .adesRequirement(EtsiAdesRequirement.builder().adesFormat(AdesType.BES).build());

      final TbsDocument tbsDocument = DocumentType.PDF.getMimeType().equals(this.signType)
          ? tbsDocumentBuilder
          .content(preparedPdfDocument.getUpdatedPdfDocument())
          .contentReference(preparedPdfDocument.getUpdatedPdfDocumentReference())
          .mimeType(DocumentType.PDF)
          .visiblePdfSignatureRequirement(preparedPdfDocument.getVisiblePdfSignatureRequirement())
          .build()
          : tbsDocumentBuilder
              .content(Base64.getEncoder()
                  .encodeToString(createSampleXml(signMessageParameters.getSignMessage()).getBytes()))
              .mimeType(DocumentType.XML)
              .build();

      final String returnUrl = this.debugFlag ? this.debugReturnUrl : null;

      final SignRequestInput input = SignRequestInput.builder()
          .correlationId(correlationId)
          .signRequesterID(this.signRequesterId)
          .returnUrl(returnUrl)
          .authnRequirements(
              AuthnRequirements.builder()
                  .authnContextClassRef(lastAuthentication.getAuthnContextUri())
                  .authnServiceID(lastAuthentication.getIdp())
                  .requestedSignerAttributes(requestedAttributes)
                  .build())
          .tbsDocument(tbsDocument)
          .signMessageParameters(signMessageParameters)
          .build();

      log.debug("SignRequestInput: {}", input);

      final SignRequestData signRequestData = this.integrationService.createSignRequest(input);

      session.setAttribute("signservice-state", signRequestData.getState());

      final ModelAndView mav = new ModelAndView("post-signrequest");
      mav.addObject("action", signRequestData.getDestinationUrl());
      mav.addObject("RelayState", signRequestData.getRelayState());
      mav.addObject("EidSignRequest", signRequestData.getSignRequest());
      return mav;
    }
    catch (final SignServiceIntegrationException e) {
      log.error("Failed to generate SignRequest for signature - {}", e.getMessage(), e);
      throw new ApplicationException("sp.msg.error.failed-sign-request", e);
    }
  }

  @PostMapping("/response")
  public ModelAndView processSignResponse(final HttpServletRequest request, final HttpServletResponse response,
      @RequestParam("EidSignResponse") final String signResponse,
      @RequestParam("RelayState") final String relayState) throws ApplicationException {

    log.info("RelayState: {}", relayState);
    log.info("EidSignResponse: {}", signResponse);

    log.info("SignResponse: {}", new String(Base64.getDecoder().decode(signResponse)));

    final HttpSession session = request.getSession();

    final SignatureState state = (SignatureState) session.getAttribute("signservice-state");
    if (state == null) {
      throw new ApplicationException("sp.msg.error.no-session", "No signature state found");
    }
    if (!relayState.equals(state.getId())) {
      throw new ApplicationException("sp.msg.error.no-session", "No signature state does not match RelayState");
    }
    session.removeAttribute("signservice-state");

    final String signMessage = (String) session.getAttribute("sign-message");
    session.removeAttribute("sign-message");

    final ModelAndView mav = new ModelAndView();

    try {
      final SignatureResult result = this.integrationService.processSignResponse(signResponse, relayState, state, null);

      session.setAttribute("signedDocument", result.getSignedDocuments().get(0).getSignedContent());
      // TMP
      session.setAttribute("signedDocumentType", result.getSignedDocuments().get(0).getMimeType());

      mav.addObject("authenticationInfo", this.createAuthenticationInfo(result));
      mav.addObject("signMessage", signMessage);
      mav.addObject("signedDocumentPath", "/signed");
      mav.setViewName("success-sign");
    }
    catch (final SignResponseCancelStatusException e) {
      log.info("User cancelled signature operation");
      return new ModelAndView("redirect:../");
    }
    catch (final SignResponseErrorStatusException e) {
      log.info("SignService reported error: {}:{} - {}", e.getMajorCode(), e.getMinorCode(), e.getMessage());
      mav.setViewName("sign-error");
      mav.addObject("status", e);
    }
    catch (final SignServiceIntegrationException e) {
      log.error("Failed to process SignResponse for signature - {}", e.getMessage(), e);
      throw new ApplicationException("sp.msg.error.response-sign-processing", e);
    }

    session.setAttribute("sp-result", mav);
    return new ModelAndView("redirect:../result");
  }

  private static String createSampleXml(final String message) {
    return String.format("<?xml version=\"1.0\" encoding=\"UTF-8\"?>%s"
            + "<SampleDocument>%s  <Message>%s</Message>%s</SampleDocument>",
        System.lineSeparator(), System.lineSeparator(), message, System.lineSeparator());
  }

  private static byte[] getSamplePdf() {
    try {
      return IOUtils.toByteArray(new ClassPathResource("pdf/sample.pdf").getInputStream());
    }
    catch (final IOException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Creates an authentication info model object based on the response result.
   *
   * @param result the result from the signature service
   * @return the model
   */
  private AuthenticationInfo createAuthenticationInfo(final SignatureResult result) {
    final AuthenticationInfo authenticationInfo = new AuthenticationInfo();

    final SignerAssertionInformation sai = result.getSignerAssertionInformation();

    final String loa = sai.getAuthnContextRef();

    authenticationInfo.setLoaUri(loa);
    boolean isEidas = false;

    if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3.equals(loa) ||
        "http://id.elegnamnden.se/loa/1.0/loa3-sigmessage".equals(loa)) {
      authenticationInfo.setLoaLevelMessageCode("sp.msg.authn-according-loa3");
      authenticationInfo.setLoaLevelDescriptionCode("sp.msg.authn-according-loa.desc");
    }
    else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_UNCERTIFIED_LOA3.equals(loa) ||
        "http://id.swedenconnect.se/loa/1.0/uncertified-loa3-sigmessage".equals(loa)) {
      authenticationInfo.setLoaLevelMessageCode("sp.msg.authn-according-loa3-uncertified");
      authenticationInfo.setLoaLevelDescriptionCode("sp.msg.authn-according-loa.desc");
    }
    else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3_NONRESIDENT.equals(loa)) {
      authenticationInfo.setLoaLevelMessageCode("sp.msg.authn-according-loa3-nonresident");
      authenticationInfo.setLoaLevelDescriptionCode("sp.msg.authn-according-loa.desc");
    }
    else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA2.equals(loa) ||
        "http://id.elegnamnden.se/loa/1.0/loa2-sigmessage".equals(loa)) {
      authenticationInfo.setLoaLevelMessageCode("sp.msg.authn-according-loa2");
      authenticationInfo.setLoaLevelDescriptionCode("sp.msg.authn-according-loa.desc");
    }
    else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_UNCERTIFIED_LOA2.equals(loa)) {
      authenticationInfo.setLoaLevelMessageCode("sp.msg.authn-according-loa2-uncertified");
      authenticationInfo.setLoaLevelDescriptionCode("sp.msg.authn-according-loa.desc");
    }
    else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA2_NONRESIDENT.equals(loa)) {
      authenticationInfo.setLoaLevelMessageCode("sp.msg.authn-according-loa2-nonresident");
      authenticationInfo.setLoaLevelDescriptionCode("sp.msg.authn-according-loa.desc");
    }
    else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA4.equals(loa) ||
        "http://id.elegnamnden.se/loa/1.0/loa4-sigmessage".equals(loa)) {
      authenticationInfo.setLoaLevelMessageCode("sp.msg.authn-according-loa4");
      authenticationInfo.setLoaLevelDescriptionCode("sp.msg.authn-according-loa.desc");
    }
    else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA4_NONRESIDENT.equals(loa)) {
      authenticationInfo.setLoaLevelMessageCode("sp.msg.authn-according-loa4-nonresident");
      authenticationInfo.setLoaLevelDescriptionCode("sp.msg.authn-according-loa.desc");
    }
    else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_EIDAS_LOW.equals(loa)
        || LevelOfAssuranceUris.AUTHN_CONTEXT_URI_EIDAS_LOW_NF.equals(loa)
        || "http://id.elegnamnden.se/loa/1.0/eidas-low-sigm".equals(loa)
        || "http://id.elegnamnden.se/loa/1.0/eidas-nf-low-sigm".equals(loa)
        || LevelOfAssuranceUris.AUTHN_CONTEXT_URI_UNCERTIFIED_EIDAS_LOW.equals(loa)) {
      authenticationInfo.setLoaLevelMessageCode("sp.msg.authn-according-loa-low");
      authenticationInfo.setLoaLevelDescriptionCode("sp.msg.authn-according-loa-eidas.desc");
      authenticationInfo.setEidasAssertion(true);
      isEidas = true;

      if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_EIDAS_LOW_NF.equals(loa)
          || "http://id.elegnamnden.se/loa/1.0/eidas-nf-low-sigm".equals(loa)) {
        authenticationInfo.setNotifiedInfoMessageCode("sp.msg.authn-according-notified");
      }
      else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_EIDAS_LOW.equals(loa)
          || "http://id.elegnamnden.se/loa/1.0/eidas-nf-low-sigm".equals(loa)) {
        authenticationInfo.setNotifiedInfoMessageCode("sp.msg.authn-according-non-notified");
      }
      else {
        authenticationInfo.setNotifiedInfoMessageCode("sp.msg.authn-according-uncertified-eidas");
      }
    }
    else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_EIDAS_SUBSTANTIAL.equals(loa)
        || LevelOfAssuranceUris.AUTHN_CONTEXT_URI_EIDAS_SUBSTANTIAL_NF.equals(loa)
        || "http://id.elegnamnden.se/loa/1.0/eidas-sub-sigm".equals(loa)
        || "http://id.elegnamnden.se/loa/1.0/eidas-nf-sub-sigm".equals(loa)
        || LevelOfAssuranceUris.AUTHN_CONTEXT_URI_UNCERTIFIED_EIDAS_SUBSTANTIAL.equals(loa)) {
      authenticationInfo.setLoaLevelMessageCode("sp.msg.authn-according-loa-substantial");
      authenticationInfo.setLoaLevelDescriptionCode("sp.msg.authn-according-loa-eidas.desc");
      authenticationInfo.setEidasAssertion(true);
      isEidas = true;

      if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_EIDAS_SUBSTANTIAL_NF.equals(loa)
          || "http://id.elegnamnden.se/loa/1.0/eidas-nf-sub-sigm".equals(loa)) {
        authenticationInfo.setNotifiedInfoMessageCode("sp.msg.authn-according-notified");
      }
      else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_EIDAS_SUBSTANTIAL.equals(loa)
          || "http://id.elegnamnden.se/loa/1.0/eidas-nf-sub-sigm".equals(loa)) {
        authenticationInfo.setNotifiedInfoMessageCode("sp.msg.authn-according-non-notified");
      }
      else {
        authenticationInfo.setNotifiedInfoMessageCode("sp.msg.authn-according-uncertified-eidas");
      }
    }
    else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_EIDAS_HIGH.equals(loa)
        || LevelOfAssuranceUris.AUTHN_CONTEXT_URI_EIDAS_HIGH_NF.equals(loa)
        || "http://id.elegnamnden.se/loa/1.0/eidas-high-sigm".equals(loa)
        || "http://id.elegnamnden.se/loa/1.0/eidas-nf-high-sigm".equals(loa)
        || LevelOfAssuranceUris.AUTHN_CONTEXT_URI_UNCERTIFIED_EIDAS_HIGH.equals(loa)) {
      authenticationInfo.setLoaLevelMessageCode("sp.msg.authn-according-loa-high");
      authenticationInfo.setLoaLevelDescriptionCode("sp.msg.authn-according-loa-eidas.desc");
      authenticationInfo.setEidasAssertion(true);
      isEidas = true;

      if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_EIDAS_HIGH_NF.equals(loa)
          || "http://id.elegnamnden.se/loa/1.0/eidas-nf-high-sigm".equals(loa)) {
        authenticationInfo.setNotifiedInfoMessageCode("sp.msg.authn-according-notified");
      }
      else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_EIDAS_HIGH.equals(loa)
          || "http://id.elegnamnden.se/loa/1.0/eidas-nf-high-sigm".equals(loa)) {
        authenticationInfo.setNotifiedInfoMessageCode("sp.msg.authn-according-non-notified");
      }
      else {
        authenticationInfo.setNotifiedInfoMessageCode("sp.msg.authn-according-uncertified-eidas");
      }
    }
    else if (TestMyEidAuthnRequestGeneratorContext.EIDAS_PING_LOA.equals(loa)) {
      authenticationInfo.setLoaLevelMessageCode("sp.msg.authn-eidas-test");
      authenticationInfo.setLoaLevelDescriptionCode("sp.msg.authn-eidas-test.desc");
      isEidas = true;
    }
    else {
      log.error("Uknown LoA: {}", loa);
    }

    for (final SignerIdentityAttributeValue a : sai.getSignerAttributes()) {
      final AttributeInfo ai = this.attributeInfoRegistry.resolve(a.getName(), a.getValue(), isEidas);
      if (ai != null) {
        if (!ai.isAdvanced()) {
          authenticationInfo.getAttributes().add(ai);
        }
        else {
          authenticationInfo.getAdvancedAttributes().add(ai);
        }
      }
    }

    authenticationInfo.setAttributes(authenticationInfo.getAttributes()
        .stream()
        .sorted(Comparator.comparing(AttributeInfo::getSortOrder))
        .collect(Collectors.toList()));

    authenticationInfo.setAdvancedAttributes(authenticationInfo.getAdvancedAttributes()
        .stream()
        .sorted(Comparator.comparing(AttributeInfo::getSortOrder))
        .collect(Collectors.toList()));

    return authenticationInfo;
  }

}
