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
package se.idsec.signservice.integration.document.xml;

import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Base64;

import javax.xml.bind.JAXBException;

import org.apache.commons.lang.StringUtils;
import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.SignRequestInput;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.error.ErrorCode;
import se.idsec.signservice.integration.core.error.InputValidationException;
import se.idsec.signservice.integration.core.impl.CorrelationID;
import se.idsec.signservice.integration.core.validation.ValidationResult;
import se.idsec.signservice.integration.document.DocumentDecoder;
import se.idsec.signservice.integration.document.DocumentEncoder;
import se.idsec.signservice.integration.document.DocumentProcessingException;
import se.idsec.signservice.integration.document.DocumentType;
import se.idsec.signservice.integration.document.ProcessedTbsDocument;
import se.idsec.signservice.integration.document.TbsDocument;
import se.idsec.signservice.integration.document.TbsDocument.EtsiAdesRequirement;
import se.idsec.signservice.integration.document.impl.AbstractTbsDocumentProcessor;
import se.idsec.signservice.integration.document.impl.EtsiAdesRequirementValidator;
import se.idsec.signservice.integration.document.impl.TbsCalculationResult;
import se.idsec.signservice.security.sign.impl.StaticCredentials;
import se.idsec.signservice.security.sign.xml.XMLSigner;
import se.idsec.signservice.security.sign.xml.XMLSignerResult;
import se.idsec.signservice.security.sign.xml.impl.DefaultXMLSigner;
import se.idsec.signservice.xml.DOMUtils;
import se.swedenconnect.schemas.etsi.xades_1_3_2.SignaturePolicyIdentifier;

/**
 * Implementation of the XML TBS document processor.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class XmlTbsDocumentProcessor extends AbstractTbsDocumentProcessor<Document> {

  /** We need to use dummy keys when creating the to-be-signed bytes. */
  private final StaticCredentials staticKeys = new StaticCredentials();

  /** The document decoder. */
  private static final XmlDocumentEncoderDecoder documentEncoderDecoder = new XmlDocumentEncoderDecoder();

  /**
   * Constructor.
   */
  public XmlTbsDocumentProcessor() {
  }

  /** {@inheritDoc} */
  @Override
  public boolean supports(final TbsDocument document) {
    try {
      return DocumentType.fromMimeType(document.getMimeType()) == DocumentType.XML;
    }
    catch (IllegalArgumentException e) {
      return false;
    }
  }

  /** {@inheritDoc} */
  @Override
  public ProcessedTbsDocument preProcess(final TbsDocument document, final SignRequestInput signRequestInput, final IntegrationServiceConfiguration config, final String fieldName)
      throws InputValidationException {

    final ProcessedTbsDocument processedTbsDocument = super.preProcess(document,signRequestInput, config, fieldName);
    final TbsDocument tbsDocument = processedTbsDocument.getTbsDocument();

    if (tbsDocument.getAdesRequirement() != null) {
      if (TbsDocument.AdesType.EPES.equals(tbsDocument.getAdesRequirement().getAdesFormat())) {

        try {
          if (tbsDocument.getAdesRequirement().getSignaturePolicy() != null) {
            // If the signature policy was given in the signaturePolicy parameter we need to create a
            // SignaturePolicyIdentifier element and add that to the AdES object.
            //
            XadesQualifyingProperties xadesObject = null;
            if (tbsDocument.getAdesRequirement().getAdesObject() == null) {
              xadesObject = XadesQualifyingProperties.createXadesQualifyingProperties();
            }
            else {
              Element elm = DOMUtils.base64ToDocument(tbsDocument.getAdesRequirement().getAdesObject()).getDocumentElement();
              xadesObject = XadesQualifyingProperties.createXadesQualifyingProperties(elm);
            }
            // Assign the signature policy
            if (xadesObject.setSignaturePolicy(tbsDocument.getAdesRequirement().getSignaturePolicy())) {
              tbsDocument.getAdesRequirement().setAdesObject(DOMUtils.nodeToBase64(xadesObject.getAdesElement()));
            }

            // Reset the signature policy - it is now set in the object ...
            tbsDocument.getAdesRequirement().setSignaturePolicy(null);
          }
        }
        catch (DocumentProcessingException | JAXBException e) {
          // All errors should have been detected by the XAdesRequirementValidator ... 
          log.error("{}: Error during update of XAdES object - {}", e.getMessage(), e);
        }
      }
    }

    return processedTbsDocument;
  }

  /** {@inheritDoc} */
  @Override
  protected TbsCalculationResult calculateToBeSigned(final ProcessedTbsDocument document, final String signatureAlgorithm,
      final IntegrationServiceConfiguration config) throws DocumentProcessingException {

    final TbsDocument tbsDocument = document.getTbsDocument();
    Document domDocument = document.getDocumentObject() != null ? document.getDocumentObject(Document.class) : null;
    if (domDocument == null) {
      // Should never happen since we always set the document ...
      domDocument = this.getDocumentDecoder().decodeDocument(tbsDocument.getContent());
    }
    final boolean requireXadesSignature = tbsDocument.getAdesRequirement() != null;

    // Sign the document using a fake key - in order to obtain the to-be-signed bytes.
    //
    try {

      final XMLSigner signer = DefaultXMLSigner.builder(this.staticKeys.getSigningCredential(signatureAlgorithm))
        .signatureAlgorithm(signatureAlgorithm)
        .includeSignatureId(requireXadesSignature)
        .build();

      final XMLSignerResult preSignResult = signer.sign(domDocument);

      // Create result ...
      final TbsCalculationResult result = new TbsCalculationResult();
      result.setSigType("XML");

      // Include the canonicalized SignedInfo element.
      //
      result.setToBeSignedBytes(preSignResult.getCanonicalizedSignedInfo());

      if (log.isDebugEnabled()) {
        final Element signedInfo = preSignResult.getSignedInfo();
        log.debug("{}: Calculated SignedInfo for document '{}': {}", CorrelationID.id(), tbsDocument.getId(),
          DOMUtils.prettyPrint(signedInfo));
      }

      if (tbsDocument.getAdesRequirement() != null) {
        result.setAdesSignatureId(preSignResult.getSignatureElement().getAttribute(Constants._ATT_ID));
        if (tbsDocument.getAdesRequirement().getAdesObject() != null) {
          result.setAdesObjectBytes(Base64.getDecoder().decode(tbsDocument.getAdesRequirement().getAdesObject()));
        }
      }

      return result;
    }
    catch (SignatureException | NoSuchAlgorithmException e) {
      final String msg = String.format("Error while calculating SignedInfo for document '%s' - %s", tbsDocument.getId(), e.getMessage());
      log.error("{}: {}", CorrelationID.id(), msg, e);
      throw new DocumentProcessingException(new ErrorCode.Code("sign"), msg, e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public DocumentDecoder<Document> getDocumentDecoder() {
    return documentEncoderDecoder;
  }

  /** {@inheritDoc} */
  @Override
  public DocumentEncoder<Document> getDocumentEncoder() {
    return documentEncoderDecoder;
  }

  /** {@inheritDoc} */
  @Override
  protected EtsiAdesRequirementValidator getEtsiAdesRequirementValidator() {
    return new XAdesRequirementValidator();
  }

  /**
   * Validator for {@link EtsiAdesRequirement} objects.
   */
  public static class XAdesRequirementValidator extends EtsiAdesRequirementValidator {

    /** {@inheritDoc} */
    @Override
    public ValidationResult validate(EtsiAdesRequirement object, String objectName, Void hint) {
      ValidationResult result = new ValidationResult(objectName);
      if (object == null) {
        return result;
      }

      // If the adesObject is provided, make sure it is valid ...
      //
      XadesQualifyingProperties xadesObject = null;
      if (object.getAdesObject() != null) {
        try {
          xadesObject = XadesQualifyingProperties.createXadesQualifyingProperties(
            DOMUtils.base64ToDocument(object.getAdesObject()).getDocumentElement());
        }
        catch (DocumentProcessingException e) {
          result.rejectValue("adesObject", e.getMessage());
        }
        catch (Exception e) {
          result.rejectValue("adesObject", "Invalid encoding/type for adesObject");
        }
      }

      if (TbsDocument.AdesType.EPES.equals(object.getAdesFormat())) {
        // The signature policy must be given. Either directly or as an element in the AdES object.
        //
        if (StringUtils.isBlank(object.getSignaturePolicy()) || xadesObject == null) {
          result.rejectValue("signaturePolicy",
            "AdES requirement states Extended Policy Electronic Signature but no signature policy has been given");
        }
        else if (StringUtils.isBlank(object.getSignaturePolicy())) {
          // Ensure that the SignaturePolicyIdentifier element is present.
          //
          if (xadesObject.getSignaturePolicyIdentifier() == null) {
            result.rejectValue("adesObject",
              "AdES requirement states Extended Policy Electronic Signature but no signature policy has been given");
          }
        }
        else if (StringUtils.isNotBlank(object.getSignaturePolicy()) && xadesObject != null) {
          final SignaturePolicyIdentifier signaturePolicyIdentifier = xadesObject.getSignaturePolicyIdentifier();
          if (signaturePolicyIdentifier != null) {
            // Ensure that the signature policy parameter and the contents of the SignaturePolicyIdentifier corresponds
            // ...
            if (signaturePolicyIdentifier.getSignaturePolicyId() != null
                && signaturePolicyIdentifier.getSignaturePolicyId().getSigPolicyId() != null
                && signaturePolicyIdentifier.getSignaturePolicyId().getSigPolicyId().getIdentifier() != null) {

              final String value = signaturePolicyIdentifier.getSignaturePolicyId().getSigPolicyId().getIdentifier().getValue();
              if (value != null && !value.equals(object.getSignaturePolicy())) {
                result.rejectValue("signaturePolicy",
                  String.format("Invalid signature policy given in AdES requirement - object states '%s', but signaturePolicy is '%s'",
                    value, object.getSignaturePolicy()));
              }

            }
          }
        }
      }

      return result;
    }

  }

}
