package com.example.sslbypass_okhttp3;

import android.util.Log;

import java.lang.reflect.Method;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class SSLPiningBypass implements IXposedHookLoadPackage {

    private static final String TAG = "SSLPinningBypass";

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        Log.d(TAG, "Loaded package: " + lpparam.packageName);

        try {
            // 1. Hook SSLContext.init() for Android < 7
            hookSSLContext(lpparam);

            // 2. Hook OkHttp CertificatePinner
            hookOkHttp(lpparam);

            // 3. Hook Trustkit
            hookTrustkit(lpparam);

            // 4. Hook TrustManagerImpl for Android > 7
            hookTrustManagerImpl(lpparam);

            // 5. Hook Appcelerator
            hookAppcelerator(lpparam);

            // 6. Hook OpenSSLSocketImpl
            hookOpenSSLSocketImpl(lpparam);

            // 7. Hook PhoneGap
            hookPhoneGap(lpparam);

            // 8. Hook IBM MobileFirst
            hookIBMMobileFirst(lpparam);

            // 9. Hook IBM WorkLight
            hookIBMWorkLight(lpparam);

        } catch (Throwable t) {
            Log.e(TAG, "Error in hooking: " + t.getMessage());
        }
    }

    private void hookSSLContext(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> sslContextClass = XposedHelpers.findClass("javax.net.ssl.SSLContext", lpparam.classLoader);

            XposedBridge.hookAllMethods(sslContextClass, "init", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    Log.d(TAG, "[+] Intercepted SSLContext.init()");

                    // 创建自定义的TrustManager
                    Object customTrustManager = createCustomTrustManager(lpparam.classLoader);

                    // 替换trustManager参数
                    if (param.args.length >= 2 && param.args[1] != null) {
                        Object[] trustManagersArray = (Object[]) param.args[1];
                        if (trustManagersArray.length > 0) {
                            Object[] newTrustManagers = new Object[]{customTrustManager};
                            param.args[1] = newTrustManagers;
                            Log.d(TAG, "[+] Replaced TrustManager with custom one");
                        }
                    }
                }
            });

            Log.d(TAG, "[+] Setup custom TrustManager (Android < 7)");
        } catch (Throwable t) {
            Log.d(TAG, "[-] SSLContext hook not found: " + t.getMessage());
        }
    }

    private Object createCustomTrustManager(ClassLoader classLoader) {
        try {
            // 创建一个实现X509TrustManager接口的动态代理
            Class<?> x509TrustManagerClass = XposedHelpers.findClass("javax.net.ssl.X509TrustManager", classLoader);

            return java.lang.reflect.Proxy.newProxyInstance(
                    classLoader,
                    new Class[]{x509TrustManagerClass},
                    (proxy, method, args) -> {
                        String methodName = method.getName();
                        Log.d(TAG, "[+] Custom TrustManager called: " + methodName);

                        if (methodName.equals("checkClientTrusted")) {
                            // 什么都不做，接受所有客户端证书
                            return null;
                        } else if (methodName.equals("checkServerTrusted")) {
                            // 什么都不做，接受所有服务器证书
                            return null;
                        } else if (methodName.equals("getAcceptedIssuers")) {
                            // 返回空数组
                            return new java.security.cert.X509Certificate[0];
                        }
                        return null;
                    }
            );
        } catch (Throwable t) {
            Log.e(TAG, "Error creating custom TrustManager: " + t.getMessage());
            return null;
        }
    }

    private void hookOkHttp(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> certificatePinnerClass = XposedHelpers.findClass("okhttp3.CertificatePinner", lpparam.classLoader);

            // Hook check方法的不同重载
            Method[] methods = certificatePinnerClass.getDeclaredMethods();
            for (Method method : methods) {
                if (method.getName().equals("check")) {
                    XposedBridge.hookMethod(method, new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            String host = (String) param.args[0];
                            Log.d(TAG, "[+] Bypassing OkHTTPv3 check for: " + host);
                            // 直接返回，不执行原始方法
                            param.setResult(null);
                        }
                    });
                } else if (method.getName().equals("check$okhttp")) {
                    XposedBridge.hookMethod(method, new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            String host = (String) param.args[0];
                            Log.d(TAG, "[+] Bypassing OkHTTPv3 4.2+ check for: " + host);
                            param.setResult(null);
                        }
                    });
                }
            }

            Log.d(TAG, "[+] Loaded OkHTTPv3 hooks");
        } catch (Throwable t) {
            Log.d(TAG, "[-] OkHTTPv3 CertificatePinner not found");
        }
    }

    private void hookTrustkit(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            // Hook OkHostnameVerifier
            Class<?> okHostnameVerifierClass = XposedHelpers.findClass(
                    "com.datatheorem.android.trustkit.pinning.OkHostnameVerifier",
                    lpparam.classLoader
            );

            XposedBridge.hookAllMethods(okHostnameVerifierClass, "verify", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    Log.d(TAG, "[+] Intercepted Trustkit verify");
                    param.setResult(true);
                }
            });

            Log.d(TAG, "[+] Setup Trustkit pinning (first class)");
        } catch (Throwable t) {
            Log.d(TAG, "[-] Trustkit first class not found");
        }

        try {
            // Hook PinningTrustManager
            Class<?> pinningTrustManagerClass = XposedHelpers.findClass(
                    "com.datatheorem.android.trustkit.pinning.PinningTrustManager",
                    lpparam.classLoader
            );

            XposedBridge.hookAllMethods(pinningTrustManagerClass, "checkServerTrusted", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    Log.d(TAG, "[+] Intercepted Trustkit checkServerTrusted");
                    // 不执行原始验证
                }
            });

            Log.d(TAG, "[+] Setup Trustkit pinning (second class)");
        } catch (Throwable t) {
            Log.d(TAG, "[-] Trustkit second class not found");
        }
    }

    private void hookTrustManagerImpl(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> trustManagerImplClass = XposedHelpers.findClass(
                    "com.android.org.conscrypt.TrustManagerImpl",
                    lpparam.classLoader
            );

            XposedBridge.hookAllMethods(trustManagerImplClass, "verifyChain", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    String host = (String) param.args[2];
                    Log.d(TAG, "[+] Intercepted TrustManagerImpl (Android > 7): " + host);

                    // 返回第一个参数（untrustedChain）作为结果
                    param.setResult(param.args[0]);
                }
            });

            Log.d(TAG, "[+] Setup TrustManagerImpl (Android > 7) pinning");
        } catch (Throwable t) {
            Log.d(TAG, "[-] TrustManagerImpl not found");
        }
    }

    private void hookAppcelerator(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> appceleratorClass = XposedHelpers.findClass(
                    "appcelerator.https.PinningTrustManager",
                    lpparam.classLoader
            );

            XposedBridge.hookAllMethods(appceleratorClass, "checkServerTrusted", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    Log.d(TAG, "[+] Intercepted Appcelerator");
                    // 不执行验证
                }
            });

            Log.d(TAG, "[+] Setup Appcelerator pinning");
        } catch (Throwable t) {
            Log.d(TAG, "[-] Appcelerator not found");
        }
    }

    private void hookOpenSSLSocketImpl(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> openSSLSocketImplClass = XposedHelpers.findClass(
                    "com.android.org.conscrypt.OpenSSLSocketImpl",
                    lpparam.classLoader
            );

            XposedBridge.hookAllMethods(openSSLSocketImplClass, "verifyCertificateChain", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    Log.d(TAG, "[+] Intercepted OpenSSLSocketImpl");
                    // 不执行验证
                }
            });

            Log.d(TAG, "[+] Setup OpenSSLSocketImpl pinning");
        } catch (Throwable t) {
            Log.d(TAG, "[-] OpenSSLSocketImpl not found");
        }
    }

    private void hookPhoneGap(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> phoneGapClass = XposedHelpers.findClass(
                    "nl.xservices.plugins.sslCertificateChecker",
                    lpparam.classLoader
            );

            XposedBridge.hookAllMethods(phoneGapClass, "execute", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    Log.d(TAG, "[+] Intercepted PhoneGap sslCertificateChecker");
                    param.setResult(true);
                }
            });

            Log.d(TAG, "[+] Setup PhoneGap sslCertificateChecker pinning");
        } catch (Throwable t) {
            Log.d(TAG, "[-] PhoneGap sslCertificateChecker not found");
        }
    }

    private void hookIBMMobileFirst(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> wlClientClass = XposedHelpers.findClass(
                    "com.worklight.wlclient.api.WLClient",
                    lpparam.classLoader
            );

            XposedBridge.hookAllMethods(wlClientClass, "pinTrustedCertificatePublicKey", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    Log.d(TAG, "[+] Intercepted IBM MobileFirst pinTrustedCertificatePublicKey");
                    // 什么都不做
                }
            });

            Log.d(TAG, "[+] Setup IBM MobileFirst pinTrustedCertificatePublicKey pinning");
        } catch (Throwable t) {
            Log.d(TAG, "[-] IBM MobileFirst pinTrustedCertificatePublicKey not found");
        }
    }

    private void hookIBMWorkLight(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> worklightClass = XposedHelpers.findClass(
                    "com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning",
                    lpparam.classLoader
            );

            XposedBridge.hookAllMethods(worklightClass, "verify", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    Log.d(TAG, "[+] Intercepted IBM WorkLight HostNameVerifierWithCertificatePinning");

                    // 根据参数数量返回适当的值
                    if (param.args.length == 2) {
                        // verify(String, SSLSession) 或 verify(String, SSLSocket)
                        param.setResult(true);
                    }
                    // 其他情况不需要设置返回值
                }
            });

            Log.d(TAG, "[+] Setup IBM WorkLight HostNameVerifierWithCertificatePinning pinning");
        } catch (Throwable t) {
            Log.d(TAG, "[-] IBM WorkLight HostNameVerifierWithCertificatePinning not found");
        }
    }
}