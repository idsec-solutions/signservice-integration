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
package se.idsec.signservice.integration.dss;

import javax.xml.bind.JAXBException;

import org.w3c.dom.Element;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.core.error.impl.SignServiceProtocolException;
import se.idsec.signservice.integration.core.impl.CorrelationID;
import se.idsec.signservice.xml.JAXBMarshaller;
import se.idsec.signservice.xml.JAXBUnmarshaller;
import se.swedenconnect.schemas.csig.dssext_1_1.SignResponseExtension;
import se.swedenconnect.schemas.csig.dssext_1_1.SignTasks;
import se.swedenconnect.schemas.dss_1_0.AnyType;
import se.swedenconnect.schemas.dss_1_0.Result;
import se.swedenconnect.schemas.dss_1_0.SignResponse;
import se.swedenconnect.schemas.dss_1_0.SignatureObject;

/**
 * A wrapper for a {@link SignResponse} object where we introduce utility methods for access of extension elements.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class SignResponseWrapper extends SignResponse {

  /** Object factory for DSS objects. */
  private static se.swedenconnect.schemas.dss_1_0.ObjectFactory dssObjectFactory =
      new se.swedenconnect.schemas.dss_1_0.ObjectFactory();

  /** The wrapped SignResponse. */
  private final SignResponse signResponse;

  /** The SignTasks (stored in SignatureObject). */
  private SignTasks signTasks;

  /** The SignResponseExtension (stored in OptionalOutputs). */
  private SignResponseExtension signResponseExtension;

  /**
   * Constructor.
   * 
   * @param signResponse
   *          the wrapped sign response
   */
  public SignResponseWrapper(final SignResponse signResponse) {
    this.signResponse = signResponse;
  }

  /**
   * Gets the wrapped SignResponse.
   * 
   * @return the wrapped SignResponse
   */
  public SignResponse getWrappedSignResponse() {
    return this.signResponse;
  }

  /** {@inheritDoc} */
  @Override
  public SignatureObject getSignatureObject() {
    return this.signResponse.getSignatureObject();
  }

  /** {@inheritDoc} */
  @Override
  public void setSignatureObject(SignatureObject value) {
    this.signTasks = null;
    this.signResponse.setSignatureObject(value);
  }

  /** {@inheritDoc} */
  @Override
  public boolean isSetSignatureObject() {
    return this.signResponse.isSetSignatureObject();
  }

  /**
   * Utility method that gets the {@code SignTasks} object from the {@code SignatureObject}.
   * 
   * @return the SignTasks (or null)
   * @throws SignServiceProtocolException
   *           for unmarshalling errors
   */
  public SignTasks getSignTasks() throws SignServiceProtocolException {
    if (this.signTasks != null) {
      return this.signTasks;
    }
    if (this.signResponse.getSignatureObject() == null || this.signResponse.getSignatureObject().getOther() == null) {
      return null;
    }
    final Element signTasksElement = this.signResponse.getSignatureObject().getOther().getAnies().stream()
      .filter(e -> "SignTasks".equals(e.getLocalName()))
      .filter(e -> DssUtils.DSS_EXT_NAMESPACE.equals(e.getNamespaceURI()))
      .findFirst()
      .orElse(null);
    if (signTasksElement != null) {
      try {
        this.signTasks = JAXBUnmarshaller.unmarshall(signTasksElement, SignTasks.class);
      }
      catch (JAXBException e) {
        log.error("{}: Failed to decode SignTasks element - {}", CorrelationID.id(), e.getMessage(), e);
        throw new SignServiceProtocolException("Failed to decode SignTasks", e);
      }
    }
    return this.signTasks;
  }

  /** {@inheritDoc} */
  @Override
  public Result getResult() {
    return this.signResponse.getResult();
  }

  /** {@inheritDoc} */
  @Override
  public void setResult(Result value) {
    this.signResponse.setResult(value);
  }

  /** {@inheritDoc} */
  @Override
  public boolean isSetResult() {
    return this.signResponse.isSetResult();
  }

  /** {@inheritDoc} */
  @Override
  public AnyType getOptionalOutputs() {
    return this.signResponse.getOptionalOutputs();
  }

  /** {@inheritDoc} */
  @Override
  public void setOptionalOutputs(AnyType value) {
    // Reset our cache for signResponseExtension.
    this.signResponseExtension = null;
    this.signResponse.setOptionalOutputs(value);
  }

  /** {@inheritDoc} */
  @Override
  public boolean isSetOptionalOutputs() {
    return this.signResponse.isSetOptionalOutputs();
  }

  /**
   * Gets the {@code SignResponseExtension} element from the {@code OptionalOutput} object.
   * 
   * @return the SignResponseExtension (or null)
   * @throws SignServiceProtocolException
   *           for unmarshalling errors
   */
  public SignResponseExtension getSignResponseExtension() throws SignServiceProtocolException {
    if (this.signResponseExtension != null) {
      return this.signResponseExtension;
    }
    if (this.signResponse.getOptionalOutputs() == null || !this.signResponse.getOptionalOutputs().isSetAnies()) {
      return null;
    }
    final Element signResponseExtensionElement = this.signResponse.getOptionalOutputs().getAnies().stream()
      .filter(e -> "SignResponseExtension".equals(e.getLocalName()))
      .filter(e -> DssUtils.DSS_EXT_NAMESPACE.equals(e.getNamespaceURI()))
      .findFirst()
      .orElse(null);
    if (signResponseExtensionElement != null) {
      try {
        this.signResponseExtension = JAXBUnmarshaller.unmarshall(signResponseExtensionElement, SignResponseExtension.class);
      }
      catch (JAXBException e) {
        log.error("Failed to decode SignResponseExtension - {}", e.getMessage(), e);
        throw new SignServiceProtocolException("Failed to decode SignResponseExtension", e);
      }
    }
    return this.signResponseExtension;
  }

  /**
   * Assigns the SignResponseExtension by adding it to OptionalOutputs.
   * <p>
   * Note: If the OptionalOutputs already contains data it is overwritten.
   * </p>
   * 
   * @param signResponseExtension
   *          the extension to add
   * @throws SignServiceProtocolException
   *           for JAXB errors
   */
  public void setSignResponseExtension(final SignResponseExtension signResponseExtension) throws SignServiceProtocolException {
    if (signResponseExtension == null) {
      this.signResponse.setOptionalOutputs(null);
      this.signResponseExtension = null;
      return;
    }

    try {
      AnyType optionalOutputs = dssObjectFactory.createAnyType();
      optionalOutputs.getAnies().add(JAXBMarshaller.marshall(signResponseExtension).getDocumentElement());
      this.signResponse.setOptionalOutputs(optionalOutputs);
      this.signResponseExtension = signResponseExtension;
    }
    catch (JAXBException e) {
      log.error("Failed to marshall SignResponseExtension - {}", e.getMessage(), e);
      throw new SignServiceProtocolException("Failed to marshall SignResponseExtension", e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public String getRequestID() {
    return this.signResponse.getRequestID();
  }

  /** {@inheritDoc} */
  @Override
  public void setRequestID(String value) {
    this.signResponse.setRequestID(value);
  }

  /** {@inheritDoc} */
  @Override
  public boolean isSetRequestID() {
    return this.signResponse.isSetRequestID();
  }

  /** {@inheritDoc} */
  @Override
  public String getProfile() {
    return this.signResponse.getProfile();
  }

  /** {@inheritDoc} */
  @Override
  public void setProfile(String value) {
    this.signResponse.setProfile(value);
  }

  /** {@inheritDoc} */
  @Override
  public boolean isSetProfile() {
    return this.signResponse.isSetProfile();
  }

}
