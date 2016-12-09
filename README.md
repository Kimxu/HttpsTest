
# 概述
> 接上一篇 [上篇点我](https://kimxu.herokuapp.com/posts/use_http_1/)
> 主要讲解下Https链接之后，的验证方式和代码实现


#验证方式
App客户端连接服务器有很多种方式：
1. 使用第三方机构颁发的证书，直接连接不做其他处理。
2. 使用自OpenSSl自签证证书，在`X509TrustManager`的`checkServerTrusted`方法中进行
自定义处理。其中处理也分为两种方式：

    2.1. 把自签证的证书存储到移动端项目中,进行Https链接的时候，对证书进行对比，如果通过就
    认为服务器是可信任的。
    2.2. 把证书中的公钥链提取出来（是一堆字符串），存储到项目中，每次链接对比证书中的公钥链。
    如果公钥链中的所有公钥都匹配上，那么就连接成功。
    
    其中2.1与2.2的区别是，证书会存在一个过期的问题，如果证书过期了，那么就匹配不上了。所以然而
    2.2的方法就没有这么一个限制，因为就算更换证书了，证书的公钥是不会更改的。
    
1.中的方法不对https连接进行自定义验证，会出现代理攻击的可能，比如说Mac上使用charles，Windows
上使用Finder，对Https进行抓包，就是把自己的证书存到手机里面，就可以进行对手机的Https连接抓包了。


#代码逻辑实现

##2.1实现方式
 
连接代码： 
``` JAVA
 URL url = new URL(targetUrl);
        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, new TrustManager[]{new LocalTrustStoreTrustManager(loadKeyStore(context))}, new SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        HttpsURLConnection urlConnection = (HttpsURLConnection) url.openConnection();
        urlConnection.setRequestMethod("GET");
        urlConnection.connect();
        return urlConnection.getInputStream();
```

其中`LocalTrustStoreTrustManager`的代码：
``` JAVA
//初始化读取到App中存储的证书
public LocalTrustStoreTrustManager(KeyStore localTrustStore) {
    try {
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init(localTrustStore);
        mTrustManager = findX509TrustManager(factory);
        if (mTrustManager == null) {
            throw new IllegalStateException("Couldn't find X509TrustManager");
        }
    } catch (GeneralSecurityException e) {
        throw new RuntimeException(e);
    }
}


//对服务器证书进行验证
@Override
public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
    mTrustManager.checkServerTrusted(chain, authType);
}
```

##2.2实现方式：
> 2.2 实现方式首先先把证书里面的公钥链提取出来，这里可以使用提供的类进行获取：

``` JAVA
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

    private void fetchAndPrintPinHashs(String host, int port, CalcPins calc) throws NoSuchAlgorithmException
    , KeyManagementException, IOException {
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
```

获取到的格式如下：
- - - - - 
75CA20E84051765A85A8E925BA047EAF442B031E
83244223D6CBF0A26FC7DE27CEBCA4BDA32612AD
B181081A19A4C0941FFAE89528C124C99B34ACC7
- - - - - 

把公钥链字符串存储到项目中（防止别人重新编译apk，替换公钥链字符串的话，可以在打包的时候
，使用字符串隐藏，增加破解难度。）

客户端代码如下：
``` JAVA
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
```

其中的`PublicKeyPinningTrustManager`类的`checkServerTrusted`方法如下：
``` JAVA
@Override
public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
    for (X509Certificate certificate : chain) {
        final boolean expected = validateCertificatePin(certificate);
        if (!expected) {
            throw new CertificateException("could not find a valid pin");
        }
    }
}
```

其中`validateCertificatePin`方法对公钥进行验证，看是否和项目中存储的公钥相匹配。

有些观点还是自己的思想，有可能说的不对，如果有什么不对的地方，欢迎指正出来~谢谢您能读到这里。
[更多点我](https://kimxu.herokuapp.com/posts/use_http_1/)


