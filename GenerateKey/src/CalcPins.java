import java.io.IOException;
import java.security.KeyManagementException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Created by kimxu on 2016/11/17.
 */

public class CalcPins {
    private MessageDigest mDigest;

    public CalcPins() throws Exception {
        mDigest = MessageDigest.getInstance("SHA1");
    }

    public static void main(String[] args) {
        if (args.length == 1 || args.length == 2) {
            String[] hostAndPort = args[0].split(":");
            String host = hostAndPort[0];
            int port = (hostAndPort.length == 1) ? 443 : Integer.parseInt(hostAndPort[1]);
            try {
                CalcPins calc = new CalcPins();
                calc.fetchAndPrintPinHashs(host, port, calc);
            } catch (Exception e) {
                e.printStackTrace();
            }

        } else {
            System.out.print("Usage: java CalcPins <host>[:port]");
        }
    }

    private void fetchAndPrintPinHashs(String host, int port, CalcPins calc) throws NoSuchAlgorithmException, KeyManagementException, IOException {
        SSLContext context = SSLContext.getInstance("TLS");
        PublicKeyExtractingTrustManager tm = new PublicKeyExtractingTrustManager(calc.mDigest);
        context.init(null, new TrustManager[]{tm}, null);
        SSLSocketFactory factory = context.getSocketFactory();
        SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
        socket.setSoTimeout(10000);
        socket.startHandshake();
        socket.close();
    }

    private class PublicKeyExtractingTrustManager implements X509TrustManager {
        private MessageDigest mDigest;

        public PublicKeyExtractingTrustManager(MessageDigest digest) {
            mDigest = digest;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            for (X509Certificate cert : chain) {
                byte[] pubKey = cert.getPublicKey().getEncoded();
                final byte[] hash = mDigest.digest(pubKey);
                System.out.println(bytesToHex(hash));
            }
        }

        private String bytesToHex(byte[] bytes) {
            final char[] hexArray = {'0', '1', '2', '3', '4', '5','6','7','8','9','A','B','C','D','E','F'};
            char[] hexChars = new char[bytes.length * 2];
            int v;
            for (int i = 0; i < bytes.length; i++) {
                v = bytes[i] & 0xFF;
                hexChars[i * 2] = hexArray[v >>> 4];
                hexChars[i * 2 + 1] = hexArray[v & 0x0F];
            }
            return new String(hexChars);
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
//            throw new UnsupportedOperationException();
            return new X509Certificate[0];
        }
    }
}
