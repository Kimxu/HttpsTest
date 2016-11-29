package kimxu.me.https.function2;

import android.content.Context;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;

import org.apache.http.conn.ssl.SSLSocketFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;

import kimxu.me.https.R;

public class MainActivity2 extends AppCompatActivity {

    private static String[] pins = new String[]{
            "75CA20E84051765A85A8E925BA047EAF442B031E",
            "83244223D6CBF0A26FC7DE27CEBCA4BDA32612AD",
            "B181081A19A4C0941FFAE89528C124C99B34ACC7"
    };
    //百度


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }

    public InputStream uRLConnectionRequestLocalTrustStore(Context context, String targetUrl) throws Exception {
        URL url = new URL(targetUrl);
        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, new TrustManager[]{new LocalTrustStoreTrustManager(loadKeyStore(context))}, new SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        HttpsURLConnection urlConnection = (HttpsURLConnection) url.openConnection();
        urlConnection.setRequestMethod("GET");
        urlConnection.connect();
        return urlConnection.getInputStream();
    }

    public InputStream uRLConnectionRequestLocalTrustStoreWithPinning(Context context, String targetUrl) throws NoSuchAlgorithmException, KeyManagementException, IOException {
        URL url = new URL(targetUrl);
        HostnameVerifier hnv = new HostnameVerifier() {
            //验证域名
            @Override
            public boolean verify(String hostname, SSLSession session) {
                if ("www.baidu.com".equals(hostname)) {
                    return true;
                } else {
                    return false;
                }
            }
        };
        TrustManager[] trustManagers = new TrustManager[]{new PublicKeyPinningTrustManager(pins)};
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustManagers, null);
        HttpsURLConnection urlConnection = (HttpsURLConnection) url.openConnection();
        urlConnection.setSSLSocketFactory(sslContext.getSocketFactory());
        urlConnection.setHostnameVerifier(SSLSocketFactory.STRICT_HOSTNAME_VERIFIER);
        urlConnection.setHostnameVerifier(hnv);
        urlConnection.setRequestMethod("GET");
        urlConnection.connect();
        return urlConnection.getInputStream();
    }


    private static final String STORE_PASSWORD = "SZRCBME";

    private KeyStore loadKeyStore(Context context) throws Exception {
        final KeyStore keyStore = KeyStore.getInstance("BKS");
        final InputStream inputStream = context.getResources().openRawResource(R.raw.baidu);
        try {
            keyStore.load(inputStream, STORE_PASSWORD.toCharArray());
            return keyStore;
        } finally {
            inputStream.close();
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
                try {
                    InputStream inputStream = uRLConnectionRequestLocalTrustStoreWithPinning(getApplicationContext(), "https://www.baidu.com");
                    String result = inputstr2Str_Reader(inputStream, "UTF-8");
                    Log.w("Test", result);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }).start();
    }
}
