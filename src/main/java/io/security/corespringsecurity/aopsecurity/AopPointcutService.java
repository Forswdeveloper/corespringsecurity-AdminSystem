package io.security.corespringsecurity.aopsecurity;

import org.springframework.stereotype.Service;

@Service
public class AopPointcutService {

    public void pointcutSecured(){
        System.out.println("Pointcut Secured");
    }

    public void notSecured(){
        System.out.println("Pointcut Not Secured");
    }
}
