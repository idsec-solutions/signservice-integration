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
package se.idsec.signservice.integration.state.impl;

import java.io.Serializable;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import se.idsec.signservice.integration.SignRequestInput;
import se.idsec.signservice.integration.core.SignatureState;
import se.idsec.signservice.integration.state.CacheableSignatureState;
import se.idsec.signservice.integration.state.SignatureSessionState;

/**
 * Default implementation of the {@link SignatureState} interface.
 * <p>
 * It uses the {@link SignRequestInput} class to store the state between calls.
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@JsonInclude(Include.NON_NULL)
@Builder
@ToString
@NoArgsConstructor
@AllArgsConstructor
public class DefaultSignatureState implements CacheableSignatureState {

  /** For serialization. */
  private static final long serialVersionUID = 8679954351779851073L;

  /**
   * The state ID.
   *
   * @param id
   *          the state ID
   */
  @Setter
  private String id;

  /**
   * The session state.
   *
   * @param state
   *          the session state
   */
  @Setter
  private SignatureSessionState state;

  /** {@inheritDoc} */
  @Override
  public String getId() {
    return this.id;
  }

  /** {@inheritDoc} */
  @Override
  public Serializable getState() {
    return this.state;
  }

  /** {@inheritDoc} */
  @JsonIgnore
  @Override
  public String getOwnerId() {
    return this.state != null ? this.state.getOwnerId() : null;
  }

}
