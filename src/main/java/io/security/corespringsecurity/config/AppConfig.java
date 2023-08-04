package io.security.corespringsecurity.config;

import io.security.corespringsecurity.repository.AccessIpRepository;
import io.security.corespringsecurity.repository.ResourcesRepository;
import io.security.corespringsecurity.service.SecurityResourceService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AppConfig {
    //공통적으로 사용하는 객체를 Bean에 등록

    @Bean
    public SecurityResourceService securityResourceService(ResourcesRepository  resourcesRepository, AccessIpRepository accessIpRepository){
        SecurityResourceService securityResourceService = new SecurityResourceService(resourcesRepository,accessIpRepository);
        return securityResourceService;
    }
}
