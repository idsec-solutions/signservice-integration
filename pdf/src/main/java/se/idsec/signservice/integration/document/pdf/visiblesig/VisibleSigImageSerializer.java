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
package se.idsec.signservice.integration.document.pdf.visiblesig;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.NoArgsConstructor;
import org.bouncycastle.util.encoders.Base64;
import se.idsec.signservice.security.sign.pdf.document.VisibleSigImage;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

/**
 * Serializer for {@link VisibleSigImage} objects
 *
 * <p>
 *   This serializer allows serialization and compression of a visible signature object in order for it to be communicated over a REST API.
 *   This is essential in order to allow stateless services between pre-signing ans complete-signing processes where all state data is
 *   returned to the requesting services between each sign process.
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@NoArgsConstructor
public class VisibleSigImageSerializer {

  /**
   * Serialize a {@link VisibleSigImage} object to a compressed value in a Base64 String
   * @param sigImage object to serialize
   * @return serialized object
   * @throws IOException on invalid input
   */
  public String serializeVisibleSignatureObject(VisibleSigImage sigImage) throws IOException {
    ObjectMapper objectMapper = new ObjectMapper();
    String json = objectMapper.writeValueAsString(sigImage);
    return Base64.toBase64String(compress(json.getBytes(StandardCharsets.UTF_8)));
  }

  /**
   * Restores a {@link VisibleSigImage} object from a serialized state
   * @param serializedSignImage serialized sign image object
   * @return {@link VisibleSigImage} object
   * @throws IOException on invalid input
   * @throws DataFormatException on invalid input
   */
  public VisibleSigImage deserializeVisibleSignImage(String serializedSignImage) throws IOException, DataFormatException {
    ObjectMapper objectMapper = new ObjectMapper();
    String json = new String(decompress(Base64.decode(serializedSignImage)), StandardCharsets.UTF_8);
    VisibleSigImage visibleSignatureObject = objectMapper.readValue(json, VisibleSigImage.class);
    return visibleSignatureObject;
  }

  /**
   * Compression
   * @param data data to compress
   * @return compressed data
   * @throws IOException on invalid input
   */
  private byte[] compress(byte[] data) throws IOException {
    Deflater deflater = new Deflater();
    deflater.setInput(data);
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length);
    deflater.finish();
    byte[] buffer = new byte[1024];
    while (!deflater.finished()) {
      int count = deflater.deflate(buffer); // returns the generated code... index
      outputStream.write(buffer, 0, count);
    }
    outputStream.close();
    byte[] output = outputStream.toByteArray();
    return output;
  }

  /**
   * Decompression
   * @param data data to be inflated
   * @return inflated data
   * @throws IOException on invalid input
   * @throws DataFormatException on invalid input
   */
  private byte[] decompress(byte[] data) throws IOException, DataFormatException {
    Inflater inflater = new Inflater();
    inflater.setInput(data);
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length);
    byte[] buffer = new byte[1024];
    while (!inflater.finished()) {
      int count = inflater.inflate(buffer);
      outputStream.write(buffer, 0, count);
    }
    outputStream.close();
    byte[] output = outputStream.toByteArray();
    return output;
  }

}
