package io.security.corespringsecurity.security.aop;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.access.SecurityMetadataSource;
import org.springframework.security.access.intercept.AbstractSecurityInterceptor;
import org.springframework.security.access.intercept.InterceptorStatusToken;
import org.springframework.security.access.method.MethodSecurityMetadataSource;

public class CustomMethodSecurityInterceptor extends AbstractSecurityInterceptor implements MethodInterceptor {
    //metaDataSource를 MapBasedMethodSecurityMetadtaSource로 따로 매핑하기 위해서 만들어짐. (정적방식)
    //기존에는 DelegatingMethodSecurityMetadataSource를 사용하고있음. (동적방식)

    private MethodSecurityMetadataSource securityMetadataSource;

    public Class<?> getSecureObjectClass() {
        return MethodInvocation.class;
    }

    public Object invoke(MethodInvocation mi) throws Throwable {
        InterceptorStatusToken token = super.beforeInvocation(mi);

        Object result;
        try {
            result = mi.proceed();
        }
        finally {
            super.finallyInvocation(token);
        }
        return super.afterInvocation(token, result);
    }

    public MethodSecurityMetadataSource getSecurityMetadataSource() {
        return this.securityMetadataSource;
    }

    public SecurityMetadataSource obtainSecurityMetadataSource() {
        return this.securityMetadataSource;
    }

    public void setSecurityMetadataSource(MethodSecurityMetadataSource newSource) {
        this.securityMetadataSource = newSource;
    }
}
