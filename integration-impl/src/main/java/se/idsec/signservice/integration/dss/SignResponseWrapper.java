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
package se.idsec.signservice.integration.dss;

import java.io.Serial;
import java.io.Serializable;

import org.w3c.dom.Element;

import jakarta.xml.bind.JAXBException;
import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.core.error.impl.SignServiceProtocolException;
import se.idsec.signservice.integration.core.impl.CorrelationID;
import se.swedenconnect.schemas.csig.dssext_1_1.SignResponseExtension;
import se.swedenconnect.schemas.csig.dssext_1_1.SignTasks;
import se.swedenconnect.schemas.dss_1_0.AnyType;
import se.swedenconnect.schemas.dss_1_0.Result;
import se.swedenconnect.schemas.dss_1_0.SignResponse;
import se.swedenconnect.schemas.dss_1_0.SignatureObject;
import se.swedenconnect.xml.jaxb.JAXBMarshaller;
import se.swedenconnect.xml.jaxb.JAXBSerializable;
import se.swedenconnect.xml.jaxb.JAXBUnmarshaller;

/**
 * A wrapper for a {@link SignResponse} object where we introduce utility methods for access of extension elements.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class SignResponseWrapper extends SignResponse implements Serializable {

  @Serial
  private static final long serialVersionUID = -3618698475882073845L;

  /** Object factory for DSS objects. */
  private static final se.swedenconnect.schemas.dss_1_0.ObjectFactory dssObjectFactory =
      new se.swedenconnect.schemas.dss_1_0.ObjectFactory();

  /** The wrapped SignResponse. */
  private final JAXBSerializable<SignResponse> signResponse;

  /** The SignTasks (stored in SignatureObject). */
  private transient SignTasks signTasks;

  /** The SignResponseExtension (stored in OptionalOutputs). */
  private transient SignResponseExtension signResponseExtension;

  /**
   * Constructor setting up an empty {@code SignResponse}.
   */
  public SignResponseWrapper() {
    this.signResponse = new JAXBSerializable<>(dssObjectFactory.createSignResponse(), SignResponse.class);
  }

  /**
   * Constructor.
   *
   * @param signResponse the wrapped sign response
   */
  public SignResponseWrapper(final SignResponse signResponse) {
    this.signResponse = new JAXBSerializable<>(signResponse, SignResponse.class);
  }

  /**
   * Gets the wrapped SignResponse.
   *
   * @return the wrapped SignResponse
   */
  public SignResponse getWrappedSignResponse() {
    return this.signResponse.get();
  }

  /** {@inheritDoc} */
  @Override
  public SignatureObject getSignatureObject() {
    return this.getWrappedSignResponse().getSignatureObject();
  }

  /** {@inheritDoc} */
  @Override
  public void setSignatureObject(final SignatureObject value) {
    this.signTasks = null;
    this.getWrappedSignResponse().setSignatureObject(value);
  }

  /** {@inheritDoc} */
  @Override
  public boolean isSetSignatureObject() {
    return this.getWrappedSignResponse().isSetSignatureObject();
  }

  /**
   * Utility method that gets the {@code SignTasks} object from the {@code SignatureObject}.
   *
   * @return the SignTasks (or null)
   * @throws SignServiceProtocolException for unmarshalling errors
   */
  public SignTasks getSignTasks() throws SignServiceProtocolException {
    if (this.signTasks != null) {
      return this.signTasks;
    }
    if (this.getWrappedSignResponse().getSignatureObject() == null
        || this.getWrappedSignResponse().getSignatureObject().getOther() == null) {
      return null;
    }
    final Element signTasksElement = this.getWrappedSignResponse().getSignatureObject()
        .getOther()
        .getAnies()
        .stream()
        .filter(e -> "SignTasks".equals(e.getLocalName()))
        .filter(e -> DssUtils.DSS_EXT_NAMESPACE.equals(e.getNamespaceURI()))
        .findFirst()
        .orElse(null);
    if (signTasksElement != null) {
      try {
        this.signTasks = JAXBUnmarshaller.unmarshall(signTasksElement, SignTasks.class);
      }
      catch (final JAXBException e) {
        log.error("{}: Failed to decode SignTasks element - {}", CorrelationID.id(), e.getMessage(), e);
        throw new SignServiceProtocolException("Failed to decode SignTasks", e);
      }
    }
    return this.signTasks;
  }

  /**
   * Utility method that add a SignTasks object to {@code Other} object of the {@code SignatureObject}. Any previous
   * sign tasks set in {@code Other} will be overwritten.
   *
   * @param signTasks the object to add
   * @throws SignServiceProtocolException for marshalling errors
   */
  public void setSignTasks(final SignTasks signTasks) throws SignServiceProtocolException {
    this.signTasks = signTasks;
    if (this.getWrappedSignResponse().getSignatureObject() == null) {
      this.getWrappedSignResponse().setSignatureObject(dssObjectFactory.createSignatureObject());
    }
    if (this.getWrappedSignResponse().getSignatureObject().getOther() == null) {
      this.getWrappedSignResponse().getSignatureObject().setOther(dssObjectFactory.createAnyType());
    }

    final Element signTasksElement;
    try {
      signTasksElement = JAXBMarshaller.marshall(this.signTasks).getDocumentElement();
    }
    catch (final JAXBException e) {
      log.error("Failed to marshall SignTasks - {}", e.getMessage(), e);
      throw new SignServiceProtocolException("Failed to marshall SignTasks", e);
    }
    for (int i = 0; i < this.getWrappedSignResponse().getSignatureObject().getOther().getAnies().size(); i++) {
      final Element elm = this.getWrappedSignResponse().getSignatureObject().getOther().getAnies().get(i);
      if (elm.getLocalName().equals("SignTasks")) {
        // Overwrite this ...
        this.getWrappedSignResponse().getSignatureObject().getOther().getAnies().set(i, signTasksElement);
        return;
      }
    }
    // We didn't have to overwrite. Add it.
    this.getWrappedSignResponse().getSignatureObject().getOther().getAnies().add(signTasksElement);
  }

  /** {@inheritDoc} */
  @Override
  public Result getResult() {
    return this.getWrappedSignResponse().getResult();
  }

  /** {@inheritDoc} */
  @Override
  public void setResult(final Result value) {
    this.getWrappedSignResponse().setResult(value);
  }

  /** {@inheritDoc} */
  @Override
  public boolean isSetResult() {
    return this.getWrappedSignResponse().isSetResult();
  }

  /** {@inheritDoc} */
  @Override
  public AnyType getOptionalOutputs() {
    return this.getWrappedSignResponse().getOptionalOutputs();
  }

  /** {@inheritDoc} */
  @Override
  public void setOptionalOutputs(final AnyType value) {
    // Reset our cache for signResponseExtension.
    this.signResponseExtension = null;
    this.getWrappedSignResponse().setOptionalOutputs(value);
  }

  /** {@inheritDoc} */
  @Override
  public boolean isSetOptionalOutputs() {
    return this.getWrappedSignResponse().isSetOptionalOutputs();
  }

  /**
   * Gets the {@code SignResponseExtension} element from the {@code OptionalOutput} object.
   *
   * @return the SignResponseExtension (or null)
   * @throws SignServiceProtocolException for unmarshalling errors
   */
  public SignResponseExtension getSignResponseExtension() throws SignServiceProtocolException {
    if (this.signResponseExtension != null) {
      return this.signResponseExtension;
    }
    if (this.getWrappedSignResponse().getOptionalOutputs() == null
        || !this.getWrappedSignResponse().getOptionalOutputs().isSetAnies()) {
      return null;
    }
    final Element signResponseExtensionElement = this.getWrappedSignResponse().getOptionalOutputs()
        .getAnies()
        .stream()
        .filter(e -> "SignResponseExtension".equals(e.getLocalName()))
        .filter(e -> DssUtils.DSS_EXT_NAMESPACE.equals(e.getNamespaceURI()))
        .findFirst()
        .orElse(null);
    if (signResponseExtensionElement != null) {
      try {
        this.signResponseExtension =
            JAXBUnmarshaller.unmarshall(signResponseExtensionElement, SignResponseExtension.class);
      }
      catch (final JAXBException e) {
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
   * @param signResponseExtension the extension to add
   * @throws SignServiceProtocolException for JAXB errors
   */
  public void setSignResponseExtension(final SignResponseExtension signResponseExtension)
      throws SignServiceProtocolException {
    if (signResponseExtension == null) {
      this.getWrappedSignResponse().setOptionalOutputs(null);
      this.signResponseExtension = null;
      return;
    }

    try {
      final AnyType optionalOutputs = dssObjectFactory.createAnyType();
      optionalOutputs.getAnies().add(JAXBMarshaller.marshall(signResponseExtension).getDocumentElement());
      this.getWrappedSignResponse().setOptionalOutputs(optionalOutputs);
      this.signResponseExtension = signResponseExtension;
    }
    catch (final JAXBException e) {
      log.error("Failed to marshall SignResponseExtension - {}", e.getMessage(), e);
      throw new SignServiceProtocolException("Failed to marshall SignResponseExtension", e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public String getRequestID() {
    return this.getWrappedSignResponse().getRequestID();
  }

  /** {@inheritDoc} */
  @Override
  public void setRequestID(final String value) {
    this.getWrappedSignResponse().setRequestID(value);
  }

  /** {@inheritDoc} */
  @Override
  public boolean isSetRequestID() {
    return this.getWrappedSignResponse().isSetRequestID();
  }

  /** {@inheritDoc} */
  @Override
  public String getProfile() {
    return this.getWrappedSignResponse().getProfile();
  }

  /** {@inheritDoc} */
  @Override
  public void setProfile(final String value) {
    this.getWrappedSignResponse().setProfile(value);
  }

  /** {@inheritDoc} */
  @Override
  public boolean isSetProfile() {
    return this.getWrappedSignResponse().isSetProfile();
  }

}
