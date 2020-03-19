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

import javax.xml.bind.JAXBException;

import org.w3c.dom.Element;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.core.error.ErrorCode;
import se.idsec.signservice.integration.core.impl.CorrelationID;
import se.idsec.signservice.integration.document.DocumentProcessingException;
import se.idsec.signservice.integration.document.ades.AdesObject;
import se.idsec.signservice.integration.document.ades.AdesSigningCertificateDigest;
import se.idsec.signservice.xml.JAXBUnmarshaller;
import se.swedenconnect.schemas.etsi.xades_1_3_2.DigestAlgAndValueType;
import se.swedenconnect.schemas.etsi.xades_1_3_2.QualifyingProperties;
import se.swedenconnect.schemas.etsi.xades_1_3_2.SigningCertificateV2;

/**
 * The XAdES object for XML signatures is a {@code xades:QualifyingProperties} object.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class XadesQualifyingProperties implements AdesObject {

  /** XAdES namespace. */
  public static final String XADES_NAMESPACE = "http://uri.etsi.org/01903/v1.3.2#";

  /** The local name for the QualifyingProperties element. */
  public static final String LOCAL_NAME = "QualifyingProperties";

  /** The XAdES object. */
  private final QualifyingProperties qualifyingProperties;

  /**
   * Constructor.
   * 
   * @param qualifyingProperties
   *          the XAdES object
   */
  public XadesQualifyingProperties(final QualifyingProperties qualifyingProperties) {
    if (qualifyingProperties == null) {
      throw new IllegalArgumentException("qualifyingProperties must not be null");
    }
    this.qualifyingProperties = qualifyingProperties;
  }

  /**
   * Given the DOM element for a QualifyingProperties element a XadesQualifyingProperties object is created.
   * 
   * @param element
   *          the DOM element
   * @return a XadesQualifyingProperties object
   * @throws DocumentProcessingException
   *           for unmarshalling errors
   */
  public static XadesQualifyingProperties createXadesQualifyingProperties(final Element element) throws DocumentProcessingException {
    try {
      return new XadesQualifyingProperties(JAXBUnmarshaller.unmarshall(element, QualifyingProperties.class));
    }
    catch (JAXBException e) {
      final String msg = String.format("Failed to unmarshall object to QualifyingProperties element - %s", e.getMessage());
      log.error("{}: {}", CorrelationID.id(), msg, e);
      throw new DocumentProcessingException(new ErrorCode.Code("invalid-xades-object"), msg);
    }
  }

  /** {@inheritDoc} */
  @Override
  public AdesSigningCertificateDigest getSigningCertificateDigest() {
    if (this.qualifyingProperties.getSignedProperties() != null
        && this.qualifyingProperties.getSignedProperties().getSignedSignatureProperties() != null
        && this.qualifyingProperties.getSignedProperties().getSignedSignatureProperties().getSigningCertificateV2() != null) {
      final SigningCertificateV2 signingCert =
          this.qualifyingProperties.getSignedProperties().getSignedSignatureProperties().getSigningCertificateV2();
      if (!signingCert.getCerts().isEmpty() && signingCert.getCerts().get(0).getCertDigest() != null) {
        final DigestAlgAndValueType digest = signingCert.getCerts().get(0).getCertDigest();
        if (digest.getDigestMethod() != null && digest.getDigestMethod().getAlgorithm() != null && digest.getDigestValue() != null) {
          return AdesSigningCertificateDigest.builder()
            .digestMethod(digest.getDigestMethod().getAlgorithm())
            .digestValue(digest.getDigestValue())
            .build();
        }
      }
    }
    log.error("{}: No signing certificate digest available in xades:QualifyingProperties", CorrelationID.id());
    return null;
  }

  /**
   * Gets the {@code xades:SigningTime}.
   * 
   * @return the signing time (in millis since epoch), or null if it is not available
   */
  public Long getSigningTime() {
    if (this.qualifyingProperties.getSignedProperties() != null
        && this.qualifyingProperties.getSignedProperties().getSignedSignatureProperties() != null
        && this.qualifyingProperties.getSignedProperties().getSignedSignatureProperties().getSigningTime() != null) {
      
      return this.qualifyingProperties.getSignedProperties().getSignedSignatureProperties().getSigningTime()
        .toGregorianCalendar().getTimeInMillis();
    }
    return null;
  }

}
