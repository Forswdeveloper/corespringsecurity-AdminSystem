package io.security.corespringsecurity.service;

import io.security.corespringsecurity.security.aop.CustomMethodSecurityInterceptor;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.support.DefaultSingletonBeanRegistry;
import org.springframework.boot.web.servlet.context.AnnotationConfigServletWebServerApplicationContext;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.method.MapBasedMethodSecurityMetadataSource;
import org.springframework.security.core.parameters.P;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.util.ClassUtils;

import java.lang.reflect.Proxy;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
public class MethodSecurityService {
    private MapBasedMethodSecurityMetadataSource mapBasedMethodSecurityMetadataSource;
    private AnnotationConfigServletWebServerApplicationContext applicationContext;
    private CustomMethodSecurityInterceptor methodSecurityInterceptor;

    private Map<String,Object> proxyMap = new HashMap<>();
    private Map<String,ProxyFactory> advisedMap = new HashMap<>();
    private Map<String,Object> targetMap = new HashMap<>();

    public MethodSecurityService(MapBasedMethodSecurityMetadataSource mapBasedMethodSecurityMetadataSource, AnnotationConfigServletWebServerApplicationContext applicationContext, CustomMethodSecurityInterceptor methodSecurityInterceptor) {
        this.mapBasedMethodSecurityMetadataSource = mapBasedMethodSecurityMetadataSource;
        this.applicationContext = applicationContext;
        this.methodSecurityInterceptor = methodSecurityInterceptor;
    }

    public void addMethodSecured(String className, String roleName) throws Exception{

        int lastDotIndex = className.lastIndexOf(".");
        String methodName = className.substring(lastDotIndex + 1);
        String typeName = className.substring(0, lastDotIndex);
        Class<?> type = ClassUtils.resolveClassName(typeName, ClassUtils.getDefaultClassLoader());
        String beanName = type.getSimpleName().substring(0, 1).toLowerCase() + type.getSimpleName().substring(1);

//        ProxyFactory proxyFactory = new ProxyFactory(); //프록시 객체 생성
//        proxyFactory.setTarget(type.getDeclaredConstructor().newInstance());
//        proxyFactory.addAdvice(methodSecurityInterceptor); //advice 등록
//        Object proxy = proxyFactory.getProxy();
        ProxyFactory proxyFactory = advisedMap.get(beanName);
        Object target = targetMap.get(beanName);

        if(proxyFactory == null){
            proxyFactory = new ProxyFactory();

            if(target == null){
                proxyFactory.setTarget((type.getDeclaredConstructor().newInstance()));
            } else {
                proxyFactory.setTarget(target);
            }
            proxyFactory.addAdvice(methodSecurityInterceptor);
            advisedMap.put(beanName, proxyFactory);
        } else {
            int adviceIndex = proxyFactory.indexOf(methodSecurityInterceptor);
            if(adviceIndex == -1){
                proxyFactory.addAdvice(methodSecurityInterceptor);
            }
        }

        Object proxy = proxyMap.get(beanName);

        if(proxy == null) {
            proxy = proxyFactory.getProxy();
            proxyMap.put(beanName,proxy);

            List<ConfigAttribute> attr = Arrays.asList(new SecurityConfig(roleName));
            mapBasedMethodSecurityMetadataSource.addSecureMethod(type,methodName, attr); //인가 처리시 권한 정보 추출 설정.

            DefaultSingletonBeanRegistry registry = (DefaultSingletonBeanRegistry)applicationContext.getBeanFactory();
            registry.destroySingleton(beanName);
            registry.registerSingleton(beanName, proxy); //메소드 호출 시 프록시 객체 빈으로 대체 되어야 함.
        }
    }

    public void removeMethodSecured(String className) throws Exception{

        int lastDotIndex = className.lastIndexOf(".");
        String typeName = className.substring(0, lastDotIndex);
        Class<?> type = ClassUtils.resolveClassName(typeName, ClassUtils.getDefaultClassLoader());
        String beanName = type.getSimpleName().substring(0, 1).toLowerCase() + type.getSimpleName().substring(1);
        Object newInstance = type.getDeclaredConstructor().newInstance();

        DefaultSingletonBeanRegistry registry = (DefaultSingletonBeanRegistry) applicationContext.getBeanFactory();

        ProxyFactory proxyFactory = advisedMap.get(beanName);

        if(proxyFactory != null) {
            proxyFactory.removeAdvice(methodSecurityInterceptor);
        } else {
            registry.destroySingleton(beanName);
            registry.registerSingleton(beanName, newInstance);
            targetMap.put(beanName,newInstance);
        }
    }
}
