package burp;

import java.io.*;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.zip.GZIPInputStream;
import javax.net.ssl.*;

public class Client {

  private static final int TIMEOUT = 2000;
  private IBurpExtenderCallbacks callbacks;

  public Client(IBurpExtenderCallbacks callbacks) {
    this.callbacks = callbacks;
  }

  public String run(String request, String url, int port)
  throws IOException, KeyManagementException, KeyStoreException,
           CertificateException,
    NoSuchAlgorithmException {
    Socket socket = getSocket(url, port);
    socket.setSoTimeout(TIMEOUT);
    BufferedWriter out =
      new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), "UTF8"));
    InputStream in = socket.getInputStream();
    sendMessage(out, request);
    String response = readResponse(in);
    out.close();
    in.close();
    socket.close();
    return response;
  }

  private void sendMessage(BufferedWriter out,
                           String request) throws IOException {
    out.write(request);
    out.write("\r\n");
    out.flush();
  }

  private String readResponse(InputStream in) throws IOException {
    String stringResponse = "", rawBody = "", rawHeaders = "";
    int bodyOffset = -1;
    byte[] by = new byte[1];
    int nRead;

    while ((nRead = in.read(by, 0, by.length)) != -1) {
      stringResponse += javax.xml.bind.DatatypeConverter.printHexBinary(by);
    }

    bodyOffset = stringResponse.indexOf("0D0A0D0A");

    if (bodyOffset != -1) {
      rawBody = stringResponse.substring(bodyOffset + 8, stringResponse.length());
    }

    rawHeaders =
      new String(
      javax.xml.bind.DatatypeConverter.parseHexBinary(
        stringResponse.substring(0, bodyOffset)));

    if (rawHeaders.contains("Transfer-Encoding: chunked")) {
      rawBody = parseChunkedResponse(rawBody);
    }

    try {
      byte[] bytesBody = javax.xml.bind.DatatypeConverter.parseHexBinary(rawBody);

      if (rawBody.length() > 1 && isCompressed(bytesBody)) {
        String outStr = "";
        ByteArrayInputStream inByteArray = new ByteArrayInputStream(bytesBody);
        WorkingGZIPInputStream gzis = new WorkingGZIPInputStream(inByteArray);
        InputStreamReader reader = new InputStreamReader(gzis);
        BufferedReader pr = new BufferedReader(reader);
        String readed;

        while ((readed = pr.readLine()) != null) {
          outStr += readed;
        }

        return rawHeaders + "\n\n" + outStr;
      } else {
        return rawHeaders
               + "\n\n"
               + new String(javax.xml.bind.DatatypeConverter.parseHexBinary(rawBody));
      }
    } catch (Exception ex) {
      callbacks.printOutput(ex.getMessage());
      return "";
    }
  }

  private String parseChunkedResponse(String rawBody) {
    String resultBody = "", tmpBody = rawBody;
    String[] chunks = tmpBody.split("0D0A", 2);
    int chunkLen =
      Integer.parseInt(
        (new String(javax.xml.bind.DatatypeConverter.parseHexBinary(chunks[0]))), 16);

    while (chunkLen != 0) {
      resultBody += chunks[1].substring(0, chunkLen * 2);
      tmpBody = chunks[1].substring(chunkLen * 2 + 4);
      chunks = tmpBody.split("0D0A", 2);
      chunkLen =
        Integer.parseInt(
          (new String(javax.xml.bind.DatatypeConverter.parseHexBinary(chunks[0]))), 16);
    }

    return resultBody;
  }

  private static Socket getSocket(String url, int port)
  throws IOException, NoSuchAlgorithmException, KeyManagementException {
    if (port != 443) {
      return new Socket(url, port);
    }

    TrustManager[] trustAllCerts =
      new TrustManager[] {
    new X509TrustManager() {
      public java.security.cert.X509Certificate[] getAcceptedIssuers() {
        return null;
      }

      @Override
      public void checkClientTrusted(X509Certificate[] certs, String authType) {}

      @Override
      public void checkServerTrusted(X509Certificate[] certs, String authType) {}
    }
    };
    SSLContext sc = SSLContext.getInstance("SSL");
    sc.init(null, trustAllCerts, new java.security.SecureRandom());
    SSLSocketFactory sslsocketfactory = sc.getSocketFactory();
    return (SSLSocket) sslsocketfactory.createSocket(url, 443);
  }

  private static boolean isCompressed(final byte[] compressed) {
    return (compressed[0] == (byte)(GZIPInputStream.GZIP_MAGIC))
           && (compressed[1] == (byte)(GZIPInputStream.GZIP_MAGIC >> 8));
  }
}

class WorkingGZIPInputStream extends java.util.zip.GZIPInputStream {
  /**
   * Creates a new input stream with the specified buffer size.
   *
   * @param in the input stream
   * @param size the input buffer size
   * @exception IOException if an I/O error has occurred
   */
  public WorkingGZIPInputStream(InputStream in, int size) throws IOException {
    super(in, size);
  }

  /**
   * Creates a new input stream with a default buffer size.
   *
   * @param in the input stream
   * @exception IOException if an I/O error has occurred
   */
  public WorkingGZIPInputStream(InputStream in) throws IOException {
    super(in);
  }

  /**
   * Calls super.read() and then catch and ignore any IOExceptions that mention "Corrupt GZIP
   * trailer".
   */
  public int read(byte buf[], int off, int len) throws IOException {
    try {
      return super.read(buf, off, len);
    } catch (IOException e) {
      if (e.getMessage().indexOf("Corrupt GZIP trailer") != -1) {
        return -1;
      } else {
        throw e;
      }
    }
  }
}
