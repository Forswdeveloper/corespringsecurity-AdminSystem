package io.security.corespringsecurity.security.factory;

import io.security.corespringsecurity.service.SecurityResourceService;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.security.access.ConfigAttribute;

import java.util.LinkedHashMap;
import java.util.List;

public class MethodResourceFactoryBean implements FactoryBean<LinkedHashMap<String, List<ConfigAttribute>>> {

    //DB로부터 가져오는 데이터를 가져오는 곳.

    private SecurityResourceService securityResourceService;

    public void setResourceType(String resourceType) {
        this.resourceType = resourceType;
    }

    private String resourceType;

    private LinkedHashMap<String, List<ConfigAttribute>> resourceMap;

    public void setSecurityResourceService(SecurityResourceService securityResourceService) {
        this.securityResourceService = securityResourceService;
    }

    //DB로부터 가지고 온 데이터를 매핑하는 서비스를 호출
    @Override
    public LinkedHashMap<String, List<ConfigAttribute>> getObject() throws Exception {

        if(resourceMap == null){
            init();
        }

        return resourceMap;
    }

    private void init() {

        if("method".equals(resourceType)){
            resourceMap = securityResourceService.getMethodResourceList();
        } else if("pointcut".equals(resourceType)){
            resourceMap = securityResourceService.getPointcutResourceList();
        }
    }

    @Override
    public Class<?> getObjectType() {
        return LinkedHashMap.class;
    }

    @Override
    public boolean isSingleton() {
        return FactoryBean.super.isSingleton();
    }
}
