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

@NoArgsConstructor
public class VisibleSigImageSerializer {

  public String serializeVisibleSignatureObject(VisibleSigImage sigImage) throws IOException {
    ObjectMapper objectMapper = new ObjectMapper();
    String json = objectMapper.writeValueAsString(sigImage);
    return Base64.toBase64String(compress(json.getBytes(StandardCharsets.UTF_8)));
  }

  public VisibleSigImage deserializeVisibleSignImage(String serializedSignImage) throws IOException, DataFormatException {
    ObjectMapper objectMapper = new ObjectMapper();
    String json = new String(decompress(Base64.decode(serializedSignImage)), StandardCharsets.UTF_8);
    VisibleSigImage visibleSignatureObject = objectMapper.readValue(json, VisibleSigImage.class);
    return visibleSignatureObject;
  }

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
