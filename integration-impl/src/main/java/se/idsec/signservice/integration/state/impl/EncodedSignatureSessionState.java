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
package se.idsec.signservice.integration.state.impl;

import java.io.IOException;
import java.io.Serial;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import se.idsec.signservice.integration.state.SignatureSessionState;

/**
 * Implementation of an encoded signature session state.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@JsonInclude(Include.NON_NULL)
@Builder
public class EncodedSignatureSessionState implements Serializable {

  /** For serialization. */
  @Serial
  private static final long serialVersionUID = -4038769805839320240L;

  /** JSON mapper. */
  @JsonIgnore
  private final static ObjectMapper mapper = new ObjectMapper();

  /**
   * The state in the Base64-encoded form of the JSON-serialization of SignatureSessionState.
   */
  @Setter
  @Getter
  private String encodedState;

  /**
   * Default constructor.
   */
  public EncodedSignatureSessionState() {
    mapper.setSerializationInclusion(Include.NON_NULL);
  }

  /**
   * Constructor.
   *
   * @param encodedState
   *          the encoded state
   */
  public EncodedSignatureSessionState(final String encodedState) {
    this();
    this.encodedState = encodedState;
  }

  /**
   * Constructor.
   *
   * @param state
   *          the state
   * @throws IOException
   *           for serialization errors
   */
  public EncodedSignatureSessionState(final SignatureSessionState state) throws IOException {
    this();
    this.setSignatureSessionState(state);
  }

  /**
   * Assigns the state to be compressed.
   *
   * @param state
   *          the state
   * @throws IOException
   *           for serialization or compression errors
   */
  @JsonIgnore
  public void setSignatureSessionState(final SignatureSessionState state) throws IOException {
    final String json = mapper.writer().writeValueAsString(state);
    this.encodedState = Base64.getEncoder().encodeToString(json.getBytes(StandardCharsets.UTF_8));
  }

  /**
   * Decompresses and gets the session state.
   *
   * @return the state
   * @throws IOException
   *           for deserialization errors
   */
  @JsonIgnore
  public SignatureSessionState getSignatureSessionState() throws IOException {
    if (this.encodedState == null) {
      return null;
    }
    return mapper.readValue(Base64.getDecoder().decode(this.encodedState), SignatureSessionState.class);
  }

}
