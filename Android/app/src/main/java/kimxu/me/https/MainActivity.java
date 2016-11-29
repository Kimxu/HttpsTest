package kimxu.me.https;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.webkit.ClientCertRequest;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import org.apache.http.conn.ssl.SSLSocketFactory;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECField;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class MainActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);


    }
    private void httpsOpen() {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            InputStream caInput = new BufferedInputStream(getResources().openRawResource(R.raw.baidu));
            final Certificate ca;
            try {
                ca = cf.generateCertificate(caInput);
                Log.i("Longer", "ca=" + ((X509Certificate) ca).getSubjectDN());
                Log.i("Longer", "key=" + ((X509Certificate) ca).getPublicKey());
            } finally {
                caInput.close();
            }
            SSLContext context = SSLContext.getInstance("TLSv1", "AndroidOpenSSL");
            context.init(null, new TrustManager[]{
                    new X509TrustManager() {
                        @Override
                        public void checkClientTrusted(X509Certificate[] chain,
                                                       String authType)
                                throws CertificateException {
                        }
                        @Override
                        public void checkServerTrusted(X509Certificate[] chain,
                                                       String authType)
                                throws CertificateException {
                            for (X509Certificate cert : chain) {
                                cert.checkValidity();
                                try {
                                    cert.verify(((X509Certificate) ca).getPublicKey());
                                } catch (NoSuchAlgorithmException e) {
                                    e.printStackTrace();
                                } catch (InvalidKeyException e) {
                                    e.printStackTrace();
                                } catch (NoSuchProviderException e) {
                                    e.printStackTrace();
                                } catch (SignatureException e) {
                                    e.printStackTrace();
                                }
                            }
                        }
                        @Override
                        public X509Certificate[] getAcceptedIssuers() {
                            return new X509Certificate[0];
                        }
                    }
            }, null);


            URL url = new URL("https://www.baidu.com");
            HostnameVerifier hnv = new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    //示例
                    if ("www.baidu.com".equals(hostname)) {
                        return true;
                    } else {
                        return false;
                    }
                }
            };
            HttpsURLConnection urlConnection =
                    (HttpsURLConnection) url.openConnection();
            urlConnection.setHostnameVerifier(SSLSocketFactory.STRICT_HOSTNAME_VERIFIER);
            urlConnection.setHostnameVerifier(hnv);
            urlConnection.setSSLSocketFactory(context.getSocketFactory());
            InputStream in = urlConnection.getInputStream();
            Log.w("MainActivity", inputstr2Str_Reader(in, "UTF-8"));
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
    }


    /**
     * 利用BufferedReader实现Inputstream转换成String <功能详细描述>
     *
     * @param in
     * @return String
     */

    public static String inputstr2Str_Reader(InputStream in, String encode) {

        String str = "";
        try {
            if (encode == null || encode.equals("")) {
                // 默认以utf-8形式
                encode = "utf-8";
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, encode));
            StringBuffer sb = new StringBuffer();

            while ((str = reader.readLine()) != null) {
                sb.append(str).append("\n");
            }
            return sb.toString();
        } catch (UnsupportedEncodingException e1) {
            e1.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return str;
    }


    public void clickIt(View view) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                //httpOpen();
                httpsOpen();
            }
        }).start();
    }
}
