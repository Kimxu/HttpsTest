package kimxu.me.https.function2;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;

/**
 * Created by kimxu on 2016/11/18.
 */

public class PublicKeyPinningTrustManager implements X509TrustManager {

    private final String[] mPins;
    private final MessageDigest mDigest;

    public PublicKeyPinningTrustManager(String[] pins) throws NoSuchAlgorithmException {
        mPins = pins;
        mDigest = MessageDigest.getInstance("SHA1");
    }

    @Override
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        throw new CertificateException("Client validation not implemented");
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        for (X509Certificate certificate : chain) {
            final boolean expected = validateCertificatePin(certificate);
            if (!expected) {
                throw new CertificateException("could not find a valid pin");
            }
        }
    }


    private boolean validateCertificatePin(X509Certificate certificate) {
        final byte[] pubKeyInfo = certificate.getPublicKey().getEncoded();
        final byte[] pin = mDigest.digest(pubKeyInfo);
        final String pinAsHex = bytesToHex(pin);
        for (String validPin : mPins) {
            if (validPin.equalsIgnoreCase(pinAsHex)) {
                return true;
            }
        }
        return false;
    }

    private String bytesToHex(byte[] bytes) {
        final char[] hexArray = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
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
        return new X509Certificate[0];
    }


}
