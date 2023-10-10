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
package se.idsec.signservice.integration.document.pdf.visiblesig;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.ObjectMapper;

import se.idsec.signservice.security.sign.pdf.document.VisibleSignatureImage;

/**
 * Serializer for {@link VisibleSignatureImage} objects.
 *
 * <p>
 * This serializer allows serialization and compression of a visible signature object in order for it to be communicated
 * over a REST API. This is essential in order to allow stateless services between pre-signing ans complete-signing
 * processes where all state data is returned to the requesting services between each sign process.
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class VisibleSignatureImageSerializer {

  /** JSON object mapper. */
  private static ObjectMapper objectMapper = new ObjectMapper();

  static {
    VisibleSignatureImageSerializer.objectMapper.setSerializationInclusion(Include.NON_NULL);
  }

  private VisibleSignatureImageSerializer() {
  }

  /**
   * Serialize a {@link VisibleSignatureImage} object to a compressed value in a Base64 string.
   *
   * @param signImage object to serialize
   * @return serialized object
   * @throws IOException on invalid input
   */
  public static String serializeVisibleSignatureObject(final VisibleSignatureImage signImage) throws IOException {
    final String json = objectMapper.writeValueAsString(signImage);
    return Base64.getEncoder().encodeToString(compress(json.getBytes(StandardCharsets.UTF_8)));
  }

  /**
   * Restores a {@link VisibleSignatureImage} object from a serialized state.
   *
   * @param serializedSignImage serialized sign image object
   * @return VisibleSigImage object
   * @throws IOException on invalid input
   */
  public static VisibleSignatureImage deserializeVisibleSignImage(final String serializedSignImage) throws IOException {
    final String json = new String(decompress(Base64.getDecoder().decode(serializedSignImage)), StandardCharsets.UTF_8);
    return objectMapper.readValue(json, VisibleSignatureImage.class);
  }

  /**
   * Compression of the supplied data.
   *
   * @param data data to compress
   * @return compressed data
   * @throws IOException on invalid input
   */
  private static byte[] compress(final byte[] data) throws IOException {
    final Deflater deflater = new Deflater();
    deflater.setInput(data);
    final ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length);
    deflater.finish();
    final byte[] buffer = new byte[1024];
    while (!deflater.finished()) {
      final int count = deflater.deflate(buffer); // returns the generated code... index
      outputStream.write(buffer, 0, count);
    }
    outputStream.close();
    return outputStream.toByteArray();
  }

  /**
   * Decompression of data.
   *
   * @param data data to be inflated
   * @return inflated data
   * @throws IOException on invalid input
   */
  private static byte[] decompress(final byte[] data) throws IOException {
    try {
      final Inflater inflater = new Inflater();
      inflater.setInput(data);
      final ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length);
      final byte[] buffer = new byte[1024];
      while (!inflater.finished()) {
        final int count = inflater.inflate(buffer);
        outputStream.write(buffer, 0, count);
      }
      outputStream.close();
      return outputStream.toByteArray();
    }
    catch (final DataFormatException e) {
      throw new IOException(e);
    }
  }

}
