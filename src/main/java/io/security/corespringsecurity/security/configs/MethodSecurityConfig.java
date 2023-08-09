package io.security.corespringsecurity.security.configs;

import io.security.corespringsecurity.security.aop.CustomMethodSecurityInterceptor;
import io.security.corespringsecurity.security.factory.MethodResourceFactoryBean;
import io.security.corespringsecurity.security.factory.UrlResourcesMapFactoryBean;
import io.security.corespringsecurity.security.processor.ProtectPointcutPostProcessor;
import io.security.corespringsecurity.security.voter.IpAddressVoter;
import io.security.corespringsecurity.service.SecurityResourceService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.intercept.RunAsManager;
import org.springframework.security.access.method.MapBasedMethodSecurityMetadataSource;
import org.springframework.security.access.method.MethodSecurityMetadataSource;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleHierarchyVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

@Configuration
@EnableGlobalMethodSecurity
@Slf4j
public class MethodSecurityConfig extends GlobalMethodSecurityConfiguration{

    @Autowired
    SecurityResourceService securityResourceService;

    @Override
    protected MethodSecurityMetadataSource customMethodSecurityMetadataSource() {
        try {
            return mapBasedMethodSecurityMetadataSource();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Bean
    public MapBasedMethodSecurityMetadataSource mapBasedMethodSecurityMetadataSource() throws Exception {
        return new MapBasedMethodSecurityMetadataSource(methodResourceFactoryBean().getObject());
    }

    @Bean
    public MethodResourceFactoryBean methodResourceFactoryBean(){
        MethodResourceFactoryBean methodResourceFactoryBean = new MethodResourceFactoryBean();
        methodResourceFactoryBean.setSecurityResourceService(securityResourceService);
        methodResourceFactoryBean.setResourceType("method");
        return methodResourceFactoryBean;
    }

    @Bean
    public MethodResourceFactoryBean pointcutResourcesMapFactoryBean(){
        MethodResourceFactoryBean methodResourceFactoryBean = new MethodResourceFactoryBean();
        methodResourceFactoryBean.setSecurityResourceService(securityResourceService);
        methodResourceFactoryBean.setResourceType("pointcut");
        return methodResourceFactoryBean;
    }

    @Bean
    public ProtectPointcutPostProcessor protectPointcutPostProcessor() throws Exception {
        ProtectPointcutPostProcessor protectPointcutPostProcessor = new ProtectPointcutPostProcessor(mapBasedMethodSecurityMetadataSource());
        protectPointcutPostProcessor.setPointcutMap(pointcutResourcesMapFactoryBean().getObject());
        return protectPointcutPostProcessor;
    }

    @Bean
    public CustomMethodSecurityInterceptor customMethodSecurityInterceptor() throws Exception{
        CustomMethodSecurityInterceptor customMethodSecurityInterceptor = new CustomMethodSecurityInterceptor();
        customMethodSecurityInterceptor.setSecurityMetadataSource(mapBasedMethodSecurityMetadataSource());
        customMethodSecurityInterceptor.setAccessDecisionManager(affirmativeBased());
        customMethodSecurityInterceptor.setAfterInvocationManager(afterInvocationManager());

        RunAsManager runAsManager = runAsManager();
        if(runAsManager != null){
            customMethodSecurityInterceptor.setRunAsManager(runAsManager);
        }

        return customMethodSecurityInterceptor;
    }

    private AccessDecisionManager affirmativeBased() {
        AffirmativeBased affirmativeBased = new AffirmativeBased(getAccessDecisionVoters());
        return affirmativeBased;
    }

    private List<AccessDecisionVoter<?>> getAccessDecisionVoters() {
        List<AccessDecisionVoter<? extends  Object>> accessDecisionVoters = new ArrayList<>();
        accessDecisionVoters.add(new IpAddressVoter(securityResourceService)); //순서 중요! 다른 심의에 영항을 줘서는 안됨.
        accessDecisionVoters.add(roleVoter());
        return accessDecisionVoters;
    }

    @Bean
    public AccessDecisionVoter<? extends Object> roleVoter() {
        RoleHierarchyVoter roleHierarchyVoter = new RoleHierarchyVoter(roleHierarchy());

        return roleHierarchyVoter;
    }

    @Bean
    public RoleHierarchyImpl roleHierarchy() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        return roleHierarchy;
    }

    private UrlResourcesMapFactoryBean urlResourcesMapFactoryBean() {
        UrlResourcesMapFactoryBean urlResourcesMapFactoryBean = new UrlResourcesMapFactoryBean();
        urlResourcesMapFactoryBean.setSecurityResourceService(securityResourceService);
        return urlResourcesMapFactoryBean;
    }
//    @Bean
//    public BeanPostProcessor protectPointcutPostProcessor() throws Exception{
//        Class<?> clazz = Class.forName("org.springframework.security.config.method.ProtectPointcutPostProcessor"); //reflection방식 생성
//        Constructor<?> declaredConstructor = clazz.getDeclaredConstructor(MapBasedMethodSecurityMetadataSource.class);
//        declaredConstructor.setAccessible(true);
//
//        Object instance = declaredConstructor.newInstance(mapBasedMethodSecurityMetadataSource());
//        Method setPointcutMap = instance.getClass().getMethod("setPointcutMap", Map.class);
//        setPointcutMap.setAccessible(true);
//        setPointcutMap.invoke(instance, pointcutResourcesMapFactoryBean().getObject());
//
//        return (BeanPostProcessor)instance;
//    }
}